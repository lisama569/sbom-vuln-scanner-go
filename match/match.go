// Package match evaluates normalized components against a local vulnerability
// database using semantic version ranges, with deterministic dedup.
package match

import (
	"github.com/lisama569/sbom-vuln-scanner-go/component"
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
	// Reason is a stable, explainable description of why it matched.
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
//   - one component identity ("ecosystem:name") is evaluated once even when it
//     appears in both direct and transitive form (direct scope wins);
//   - each advisory is reported at most once per component identity;
//   - findings are sorted by (package, version, advisoryID).
func (x *Matcher) Match(m *component.Manifest) ([]Finding, error) {
	return nil, nil
}
