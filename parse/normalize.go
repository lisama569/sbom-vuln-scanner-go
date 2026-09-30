package parse

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
)

// Merge produces a normalized Manifest from raw parser output, applying the
// single, documented resolution rule for records that appear more than once:
//
//  1. Components with the same ID ("ecosystem:name@version") merge into one.
//     If one occurrence is direct and another transitive, the result is
//     ScopeDirect ("direct wins"); DependsOn sets union deterministically.
//     A Warning "scope_dedup" records every merge so it is never silent.
//  2. The same package name pinned to different versions is NOT a duplicate:
//     each version stays a distinct component. A "multiple_versions" warning
//     is attached to the package so the ambiguity is visible; later matching
//     evaluates every pinned version, so no occurrence can be silently
//     missed or double-counted.
//  3. Rejected records and parser warnings pass through sorted, preserving
//     the distinguishable reason codes.
//
// Component ordering in the returned manifest is deterministic
// (name, version), making scan conclusions independent of file ordering and
// concurrency scheduling.
func Merge(format, file string, comps []component.Component, rejected []component.Rejected, warnings []component.Warning) *component.Manifest {
	m := &component.Manifest{Format: format, File: file}

	type agg struct {
		c      component.Component
		merged int
		direct bool
		trans  bool
		depSet map[string]struct{}
		order  int
	}
	byID := map[string]*agg{}
	idsInOrder := []string{}

	for _, c := range comps {
		a := byID[c.ID()]
		if a == nil {
			a = &agg{c: c, depSet: map[string]struct{}{}}
			for _, d := range c.DependsOn {
				a.depSet[d] = struct{}{}
			}
			byID[c.ID()] = a
			idsInOrder = append(idsInOrder, c.ID())
			a.order = len(idsInOrder)
		} else {
			a.merged++
			for _, d := range c.DependsOn {
				a.depSet[d] = struct{}{}
			}
		}
		if c.Scope == component.ScopeDirect {
			a.direct = true
		}
		if c.Scope == component.ScopeTransitive {
			a.trans = true
		}
	}

	// Detect same-name different-version packages.
	byName := map[string][]string{}
	for id := range byID {
		a := byID[id]
		byName[a.c.Key()] = append(byName[a.c.Key()], a.c.Version)
	}
	multi := map[string][]string{}
	for key, vers := range byName {
		if len(vers) > 1 {
			sort.Strings(vers)
			multi[key] = vers
		}
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		ci, cj := byID[ids[i]].c, byID[ids[j]].c
		if ci.Key() != cj.Key() {
			return ci.Key() < cj.Key()
		}
		return ci.Version < cj.Version
	})

	for _, id := range ids {
		a := byID[id]
		c := a.c
		switch {
		case a.direct:
			c.Scope = component.ScopeDirect
		case a.trans:
			c.Scope = component.ScopeTransitive
		}
		deps := make([]string, 0, len(a.depSet))
		for d := range a.depSet {
			deps = append(deps, d)
		}
		sort.Strings(deps)
		c.DependsOn = deps
		m.Components = append(m.Components, c)

		if a.merged > 0 {
			scopes := []string{}
			if a.direct {
				scopes = append(scopes, "direct")
			}
			if a.trans {
				scopes = append(scopes, "transitive")
			}
			m.Warnings = append(m.Warnings, component.Warning{
				Code:   "scope_dedup",
				Detail: fmt.Sprintf("%s appeared %d time(s); merged as %s", id, a.merged+1, strings.Join(scopes, "+")),
				Source: c.Source,
			})
		}
		if vers := multi[c.Key()]; vers != nil {
			m.Warnings = append(m.Warnings, component.Warning{
				Code:   "multiple_versions",
				Detail: fmt.Sprintf("%s pinned to multiple versions: %s", c.Key(), strings.Join(vers, ", ")),
				Source: c.Source,
			})
		}
	}

	sort.Slice(rejected, func(i, j int) bool {
		if rejected[i].Source.File != rejected[j].Source.File {
			return rejected[i].Source.File < rejected[j].Source.File
		}
		return rejected[i].Source.Line < rejected[j].Source.Line
	})
	m.Rejected = append(m.Rejected, rejected...)

	sort.SliceStable(warnings, func(i, j int) bool {
		if warnings[i].Code != warnings[j].Code {
			return warnings[i].Code < warnings[j].Code
		}
		return warnings[i].Detail < warnings[j].Detail
	})
	m.Warnings = append(m.Warnings, warnings...)

	return m
}
