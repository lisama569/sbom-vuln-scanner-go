// Package gomod parses Go go.mod files.
package gomod

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
	"github.com/lisama569/sbom-vuln-scanner-go/semver"
)

// Parser implements parse.Parser for go.mod.
type Parser struct{}

// New returns a new go.mod parser.
func New() *Parser { return &Parser{} }

func (Parser) Format() string { return "gomod" }

var modulePathRE = regexp.MustCompile(`^(\.?[a-zA-Z0-9](?:[a-zA-Z0-9\-_.]*[a-zA-Z0-9])?)(?:/[a-zA-Z0-9](?:[a-zA-Z0-9\-_.]*[a-zA-Z0-9])?)*$`)

// Parse reads and normalizes a go.mod file.
//
// All require entries are ScopeDirect by convention (go.mod does not carry
// transitive pins). Replace directives that rewrite a requirement's version
// are applied (effective version) and recorded as warnings. Invalid module
// paths or versions become Rejected records (distinguishable reason, line
// number, raw text) rather than being silently dropped. A structurally
// unreadable file is a ClassParseFailed error; an unexpected panic is
// ClassInternal.
func (p Parser) Parse(ctx context.Context, path string) (m *component.Manifest, err error) {
	defer func() {
		if r := recover(); r != nil {
			m = nil
			err = &parse.Error{Class: parse.ClassInternal, Format: "gomod", Path: path,
				Err: fmt.Errorf("internal panic: %v", r)}
		}
	}()

	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, &parse.Error{Class: parse.ClassParseFailed, Format: "gomod", Path: path, Err: readErr}
	}
	lines, perr := physicalLines(string(raw))
	if perr != nil {
		return nil, &parse.Error{Class: parse.ClassParseFailed, Format: "gomod", Path: path, Err: perr}
	}

	// Pass 1: collect replace version rewrites (order-independent).
	replacements := map[string]string{}
	preWarnings := []component.Warning{}
	collectReplaces(path, lines, replacements, &preWarnings)

	// Pass 2: require entries.
	comps := []component.Component{}
	rejected := []component.Rejected{}
	warnings := append([]component.Warning{}, preWarnings...)
	inRequire := false
	for _, ln := range lines {
		text := ln.text
		switch {
		case inRequire:
			if text == ")" {
				inRequire = false
				continue
			}
			if text != "" {
				acceptRequire(path, ln, text, replacements, &comps, &rejected, &warnings)
			}
		case strings.HasPrefix(text, "require"):
			rest := strings.TrimSpace(strings.TrimPrefix(text, "require"))
			if rest == "(" {
				inRequire = true
				continue
			}
			if rest == "" {
				rejected = append(rejected, component.Rejected{
					Reason: component.RejectMalformedEntry,
					Detail: "require directive without arguments",
					Source: component.SourceRef{Format: "gomod", File: path, Line: ln.no, RawKey: "require"},
					Raw:    ln.raw})
				continue
			}
			acceptRequire(path, ln, rest, replacements, &comps, &rejected, &warnings)
		}
	}
	if inRequire {
		return nil, &parse.Error{Class: parse.ClassParseFailed, Format: "gomod", Path: path,
			Err: fmt.Errorf("unterminated require block")}
	}

	return parse.Merge("gomod", path, comps, rejected, warnings), nil
}

type line struct {
	no   int
	text string // comment-stripped, trimmed
	raw  string // original physical line, trimmed
}

func physicalLines(content string) ([]line, error) {
	var out []line
	rawLines := strings.Split(content, "\n")
	for i, rl := range rawLines {
		t := strings.TrimSpace(stripComment(rl))
		if t == "" {
			continue
		}
		if strings.Count(t, "`")%2 != 0 {
			return nil, fmt.Errorf("line %d: unbalanced quotes", i+1)
		}
		out = append(out, line{no: i + 1, text: t, raw: strings.TrimSpace(rl)})
	}
	return out, nil
}

// stripComment removes a trailing // comment outside a quoted run.
func stripComment(s string) string {
	inQ := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '`', '"':
			inQ = !inQ
		case '/':
			if !inQ && i+1 < len(s) && s[i+1] == '/' {
				return s[:i]
			}
		}
	}
	return s
}

func collectReplaces(path string, lines []line, replacements map[string]string, warnings *[]component.Warning) {
	for _, ln := range lines {
		if !strings.HasPrefix(ln.text, "replace") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(ln.text, "replace"))
		parts := strings.SplitN(body, "=>", 2)
		src := component.SourceRef{Format: "gomod", File: path, Line: ln.no, RawKey: "replace"}
		if len(parts) != 2 {
			*warnings = append(*warnings, component.Warning{
				Code: "malformed_replace", Detail: "replace without =>: " + ln.text, Source: src})
			continue
		}
		lhs := strings.Fields(strings.TrimSpace(parts[0]))
		rhs := strings.Fields(strings.TrimSpace(parts[1]))
		if len(lhs) == 0 || len(rhs) < 2 {
			*warnings = append(*warnings, component.Warning{
				Code: "malformed_replace", Detail: "replace sides incomplete or unversioned: " + ln.text, Source: src})
			continue
		}
		// lhs may be "oldPath oldVer"; only oldPath matters for mapping.
		if _, err := semver.Parse(rhs[1]); err != nil {
			*warnings = append(*warnings, component.Warning{
				Code:   "malformed_replace",
				Detail: fmt.Sprintf("replace target version %q invalid: %v", rhs[1], err), Source: src})
			continue
		}
		replacements[lhs[0]] = rhs[1]
	}
}

// acceptRequire parses one "path version" require entry and applies any
// replacement version.
func acceptRequire(path string, ln line, text string, replacements map[string]string,
	comps *[]component.Component, rejected *[]component.Rejected, warnings *[]component.Warning) {
	src := component.SourceRef{Format: "gomod", File: path, Line: ln.no, RawKey: "require"}
	fields := strings.Fields(text)
	if len(fields) < 2 {
		*rejected = append(*rejected, component.Rejected{
			Reason: component.RejectMalformedEntry,
			Detail: fmt.Sprintf("require entry needs <path> <version>, got %d field(s)", len(fields)),
			Source: src, Raw: ln.raw})
		return
	}
	if len(fields) > 2 {
		*rejected = append(*rejected, component.Rejected{
			Reason: component.RejectMalformedEntry,
			Detail: fmt.Sprintf("require entry has %d fields, want 2", len(fields)),
			Source: src, Raw: ln.raw})
		return
	}
	name := fields[0] // /v2 suffix is part of the module path and preserved.
	ver := fields[1]
	if !modulePathRE.MatchString(name) {
		*rejected = append(*rejected, component.Rejected{
			Reason: component.RejectMissingName,
			Detail: fmt.Sprintf("invalid module path %q", name),
			Source: src, Raw: ln.raw})
		return
	}
	if _, verr := semver.Parse(ver); verr != nil {
		*rejected = append(*rejected, component.Rejected{
			Reason: component.RejectInvalidVersion,
			Detail: fmt.Sprintf("module %s version %q: %v", name, ver, verr),
			Source: src, Raw: ln.raw})
		return
	}
	pv, _ := semver.Parse(ver)
	ver = pv.String() // canonical form (strip the tolerated leading "v")
	if rv, ok := replacements[name]; ok {
		rvv, _ := semver.Parse(rv)
		w := component.Warning{
			Code:   "replace_version",
			Detail: fmt.Sprintf("%s %s replaced by %s", name, ver, rvv.String()),
			Source: src}
		*warnings = append(*warnings, w)
		ver = rvv.String()
	}
	*comps = append(*comps, component.Component{
		Ecosystem: "gomod", Name: name, Version: ver, Scope: component.ScopeDirect, Source: src})
}

func init() { parse.Register(New()) }
