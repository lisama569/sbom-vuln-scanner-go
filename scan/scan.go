// Package scan orchestrates parsing one target and matching it against the
// database, with explicit three-way error classification.
package scan

import (
	"context"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/match"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
)

// FailureClass distinguishes target-level failure kinds.
type FailureClass int

const (
	FailureNone FailureClass = iota
	// FailureTarget means the single target could not be processed (bad path,
	// malformed file / parse-failed error).
	FailureTarget
	// FailureInternal means the parser/matcher reported an unexpected internal
	// error, distinct from bad input.
	FailureInternal
)

func (c FailureClass) String() string {
	switch c {
	case FailureTarget:
		return "target_failed"
	case FailureInternal:
		return "internal"
	default:
		return "none"
	}
}

// Failure captures one classified target failure.
type Failure struct {
	Class  FailureClass
	Target Target
	Err    error
}

func (f Failure) Error() string {
	return f.Class.String() + ": " + f.Target.Path + ": " + f.Err.Error()
}

// Target names one manifest file and the parser format to use.
type Target struct {
	Format string
	Path   string
}

// Key is the deterministic cache key of a target.
func (t Target) Key() string { return t.Format + ":" + t.Path }

// Result is the per-target scan outcome. When Failure != nil, the other
// fields must not be interpreted as a successful scan.
type Result struct {
	Target   Target
	Manifest *component.Manifest
	Findings []match.Finding
	Failure  *Failure
}

// Scanner scans single targets.
type Scanner struct {
	db *vulndb.Database
}

// New creates a Scanner bound to db.
func New(db *vulndb.Database) *Scanner { return &Scanner{db: db} }

// Scan parses and matches one target.
func (s *Scanner) Scan(ctx context.Context, t Target) *Result { return nil }

// ensure parse import is used in skeleton
var _ = parse.ClassOK
