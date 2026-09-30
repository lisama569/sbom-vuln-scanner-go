// Package match evaluates normalized components against a local vulnerability
// database using semantic version ranges, with deterministic dedup.
package match

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/semver"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
)

// Finding is one component/advisory match with human-explainable evidence.
type Finding struct {
	AdvisoryID string
	Ecosystem  string
	Package    string
	Version    string
	Scope      component.Scope
	// MatchedRange is the 0-based index into Advisory.Affected that matched.
	MatchedRange int
	// Reason is a stable, explainable description of the decision basis.
	Reason string
}

// Matcher matches manifests against one immutable database snapshot.
type Matcher struct {
	db *vulndb.Database
}

// New creates a Matcher bound to db.
func New(db *vulndb.Database) *Matcher { return &Matcher{db: db} }

// Match matches every component in m against the database.
//
// Determinism rules:
//   - components are evaluated in Manifest order (already deterministic from
//     parse.Merge), so direct/transitive duplicate and concurrency scheduling
//     cannot change conclusions;
//   - each component instance ID is evaluated once (parser-level dedup already
//     guarantees this); each advisory is reported at most once per instance;
//   - same package pinned to multiple versions is evaluated independently, so
//     no vulnerable pin can be missed and no advisory is double-counted;
//   - findings are sorted by (package, version, advisoryID).
func (x *Matcher) Match(m *component.Manifest) ([]Finding, error) {
	if m == nil {
		return nil, fmt.Errorf("match: nil manifest")
	}
	if x.db == nil {
		return nil, fmt.Errorf("match: nil vulnerability database")
	}

	findings := []Finding{}
	for _, c := range m.Components {
		parsed, err := semver.Parse(c.Version)
		if err != nil {
			// Canonical versions should always parse; treat as internal to
			// keep the failure class distinguishable downstream.
			return nil, fmt.Errorf("match: component %s: %w", c.ID(), err)
		}
		for _, adv := range x.db.ForPackage(c.Ecosystem, c.Name) {
			for ri, r := range adv.Affected {
				ok, reason, err := groupHolds(r, parsed)
				if err != nil {
					return nil, fmt.Errorf("match: advisory %s range #%d: %w", adv.ID, ri+1, err)
				}
				if ok {
					findings = append(findings, Finding{
						AdvisoryID:   adv.ID,
						Ecosystem:    c.Ecosystem,
						Package:      c.Name,
						Version:      c.Version,
						Scope:        c.Scope,
						MatchedRange: ri,
						Reason: fmt.Sprintf("version %s satisfies %s (group #%d): %s; advisory=%s summary=%q",
							c.Version, rangeText(r), ri+1, reason, adv.ID, adv.Summary),
					})
					break // first matching AND group wins per advisory; report once
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.AdvisoryID < b.AdvisoryID
	})
	return findings, nil
}

// groupHolds evaluates an advisory AND group, rebuilding bounds from their raw
// strings (they were validated at DB load, so errors here are internal). The
// returned reason lists every boundary check for explainability.
func groupHolds(r vulndb.Range, v semver.Version) (bool, string, error) {
	checks := make([]string, 0, len(r.Bounds))
	all := true
	for _, b := range r.Bounds {
		bv, err := semver.Parse(b.Ver)
		if err != nil {
			return false, "", err
		}
		bound := semver.Bound{Op: semver.Operator(b.Op), V: bv}
		holds := bound.Holds(v)
		checks = append(checks, fmt.Sprintf("%s(%s)=%t", bound, v, holds))
		if !holds {
			all = false
		}
	}
	return all, strings.Join(checks, " AND "), nil
}

func rangeText(r vulndb.Range) string {
	parts := make([]string, 0, len(r.Bounds))
	for _, b := range r.Bounds {
		parts = append(parts, b.Op+b.Ver)
	}
	return strings.Join(parts, " ")
}
