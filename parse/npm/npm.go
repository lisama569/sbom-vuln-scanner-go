// Package npm parses npm package-lock.json files (lockfileVersion 1, 2 and 3).
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
	"github.com/lisama569/sbom-vuln-scanner-go/semver"
)

// Parser implements parse.Parser for package-lock.json.
type Parser struct{}

// New returns a new npm lockfile parser.
func New() *Parser { return &Parser{} }

func (Parser) Format() string { return "npm" }

// lockfile structures. Fields use pointers/RawMessage so that missing versus
// present-but-wrong types can be distinguished in rejection messages.
type lockPkg struct {
	Version      string            `json:"version"`
	Name         string            `json:"name"`
	Resolved     string            `json:"resolved"`
	Link         bool              `json:"link"`
	Dev          bool              `json:"dev"`
	Optional     bool              `json:"optional"`
	Dependencies map[string]string `json:"dependencies"`
	Requires     map[string]string `json:"requires"`
}

type lockfile struct {
	Name            string               `json:"name"`
	LockfileVersion *json.RawMessage     `json:"lockfileVersion"`
	Packages        map[string]lockPkg   `json:"packages"`
	Dependencies    map[string]lockV1Dep `json:"dependencies"`
}

type lockV1Dep struct {
	Version      string               `json:"version"`
	Dependencies map[string]lockV1Dep `json:"dependencies"`
	Requires     map[string]string    `json:"requires"`
}

// Parse reads and normalizes a package-lock.json.
func (p Parser) Parse(ctx context.Context, path string) (m *component.Manifest, err error) {
	// Internal errors (panics) are classified separately from bad input.
	defer func() {
		if r := recover(); r != nil {
			m = nil
			err = &parse.Error{Class: parse.ClassInternal, Format: "npm", Path: path,
				Err: fmt.Errorf("internal panic: %v", r)}
		}
	}()

	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, &parse.Error{Class: parse.ClassParseFailed, Format: "npm", Path: path, Err: readErr}
	}

	// Strict structural pass: malformed JSON fails the whole target distinctly.
	if jerr := json.Unmarshal(raw, &map[string]json.RawMessage{}); jerr != nil {
		return nil, &parse.Error{Class: parse.ClassParseFailed, Format: "npm", Path: path,
			Err: fmt.Errorf("malformed package-lock.json: %w", jerr)}
	}

	var lf lockfile
	if decErr := json.Unmarshal(raw, &lf); decErr != nil {
		// Typed decoding failing after structural pass = structurally odd
		// record types (e.g. version given as a number): classify as
		// parse_failed because the input does not match the lockfile schema.
		return nil, &parse.Error{Class: parse.ClassParseFailed, Format: "npm", Path: path,
			Err: fmt.Errorf("schema mismatch: %w", decErr)}
	}

	comps, rejected, warnings := []component.Component{}, []component.Rejected{}, []component.Warning{}

	switch {
	case len(lf.Packages) > 0:
		parseV2V3(&lf, path, &comps, &rejected, &warnings)
	case len(lf.Dependencies) > 0:
		parseV1(&lf, path, &comps, &rejected, &warnings)
	default:
		return nil, &parse.Error{Class: parse.ClassParseFailed, Format: "npm", Path: path,
			Err: fmt.Errorf("lockfile has neither packages(v2/v3) nor dependencies(v1)")}
	}

	return parse.Merge("npm", path, comps, rejected, warnings), nil
}

// parseV2V3 handles lockfileVersion 2/3. packages[""] is the root: its
// dependencies/devDependencies are the direct set; every installed package
// node_modules/<name> (including nested node_modules) is a record.
func parseV2V3(lf *lockfile, path string, comps *[]component.Component, rejected *[]component.Rejected, warnings *[]component.Warning) {
	direct := map[string]struct{}{}
	if root, ok := lf.Packages[""]; ok {
		for n := range root.Dependencies {
			direct[n] = struct{}{}
		}
		// v2 root dev deps are expressed as entries flagged dev, but some
		// toolchains also keep them under root requires-like fields; the
		// packages-map flag below is authoritative for scope.
	}

	// Deterministic traversal.
	keys := make([]string, 0, len(lf.Packages))
	for k := range lf.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if key == "" {
			continue
		}
		src := component.SourceRef{Format: "npm", File: path, RawKey: key}
		pkg := lf.Packages[key]

		if pkg.Link {
			*warnings = append(*warnings, component.Warning{
				Code: "link_skipped", Detail: fmt.Sprintf("%s is a workspace/symlink entry; not a published package", key), Source: src})
			continue
		}

		name := pkg.Name
		if name == "" {
			name = nameFromPath(key)
		}
		// A scoped/nested path must end with the declared name; mismatch means
		// an incomplete/ambiguous record.
		if name == "" {
			*rejected = append(*rejected, component.Rejected{
				Reason: component.RejectMissingName,
				Detail: "cannot derive package name from packages key and 'name' is absent",
				Source: src, Raw: rawKeyV2(key, pkg)})
			continue
		}
		if derived := nameFromPath(key); derived != "" && derived != name {
			*warnings = append(*warnings, component.Warning{
				Code:   "name_path_mismatch",
				Detail: fmt.Sprintf("declared name %q differs from path-derived %q; using path-derived name", name, derived),
				Source: src})
			name = derived
		}

		if strings.TrimSpace(pkg.Version) == "" {
			*rejected = append(*rejected, component.Rejected{
				Reason: component.RejectMissingVersion,
				Detail: fmt.Sprintf("package %s has empty/missing version", name),
				Source: src, Raw: rawKeyV2(key, pkg)})
			continue
		}
		if _, verr := semver.Parse(strings.TrimSpace(pkg.Version)); verr != nil {
			*rejected = append(*rejected, component.Rejected{
				Reason: component.RejectInvalidVersion,
				Detail: fmt.Sprintf("package %s version %q: %v", name, pkg.Version, verr),
				Source: src, Raw: rawKeyV2(key, pkg)})
			continue
		}

		scope := component.ScopeTransitive
		if _, isDirect := direct[name]; isDirect && !isNested(key) {
			scope = component.ScopeDirect
		}
		// v2/v3: top-level node_modules entry flagged dev is still a direct
		// dependency of the root project.
		if !isNested(key) && rootDeclares(lf, name) {
			scope = component.ScopeDirect
		}

		c := component.Component{
			Ecosystem: "npm", Name: name, Version: strings.TrimSpace(pkg.Version),
			Scope: scope, Source: src,
		}
		c.DependsOn = appendDepNames(c.DependsOn, pkg.Dependencies)
		c.DependsOn = appendDepNames(c.DependsOn, pkg.Requires)
		*comps = append(*comps, c)
	}
}

// parseV1 flattens the v1 dependency tree. Top-level keys are direct, nested
// "dependencies" children are transitive.
func parseV1(lf *lockfile, path string, comps *[]component.Component, rejected *[]component.Rejected, warnings *[]component.Warning) {
	var walk func(name string, d lockV1Dep, direct bool, key string)
	walk = func(name string, d lockV1Dep, direct bool, key string) {
		src := component.SourceRef{Format: "npm", File: path, RawKey: key}
		if strings.TrimSpace(name) == "" {
			*rejected = append(*rejected, component.Rejected{
				Reason: component.RejectMissingName, Detail: "v1 tree node without name", Source: src, Raw: key})
			return
		}
		if strings.TrimSpace(d.Version) == "" {
			*rejected = append(*rejected, component.Rejected{
				Reason: component.RejectMissingVersion, Detail: "v1 node " + name + " without version", Source: src, Raw: key})
		} else if _, verr := semver.Parse(strings.TrimSpace(d.Version)); verr != nil {
			*rejected = append(*rejected, component.Rejected{
				Reason: component.RejectInvalidVersion,
				Detail: fmt.Sprintf("v1 node %s version %q: %v", name, d.Version, verr), Source: src, Raw: key})
		} else {
			scope := component.ScopeTransitive
			if direct {
				scope = component.ScopeDirect
			}
			c := component.Component{Ecosystem: "npm", Name: name, Version: strings.TrimSpace(d.Version), Scope: scope, Source: src}
			c.DependsOn = appendDepNames(c.DependsOn, d.Requires)
			*comps = append(*comps, c)
		}
		// Deterministic recursion.
		childNames := make([]string, 0, len(d.Dependencies))
		for n := range d.Dependencies {
			childNames = append(childNames, n)
		}
		sort.Strings(childNames)
		for _, n := range childNames {
			walk(n, d.Dependencies[n], false, key+">dependencies>"+n)
		}
	}
	names := make([]string, 0, len(lf.Dependencies))
	for n := range lf.Dependencies {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		walk(n, lf.Dependencies[n], true, "dependencies>"+n)
	}
}

func rootDeclares(lf *lockfile, name string) bool {
	root := lf.Packages[""]
	for n := range root.Dependencies {
		if n == name {
			return true
		}
	}
	return false
}

// nameFromPath extracts the package name from a packages-map key such as
// "node_modules/a" or "node_modules/a/node_modules/@scope/b". Returns "" for
// the root key or non-installed entries (e.g. "bin").
func nameFromPath(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		return ""
	}
	rest := key[idx+len("node_modules/"):]
	if rest == "" {
		return ""
	}
	if strings.HasPrefix(rest, "@") {
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[1] == "" {
			return ""
		}
	}
	return rest
}

func isNested(key string) bool {
	idx := strings.LastIndex(key, "node_modules/")
	return idx > len("node_modules/") // another node_modules precedes the last
}

func appendDepNames(in []string, m map[string]string) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return append(in, names...)
}

func rawKeyV2(key string, pkg lockPkg) string {
	return fmt.Sprintf("packages[%q]={version:%q name:%q link:%t}", key, pkg.Version, pkg.Name, pkg.Link)
}
