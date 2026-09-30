// Package scan orchestrates parsing one target and matching it against the
// database, with explicit three-way error classification.
package scan

import (
	"context"
	"errors"
	"fmt"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/match"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
)

// FailureClass distinguishes target-level failure kinds.
type FailureClass int

const (
	FailureNone FailureClass = iota
	// FailureTarget means the single target could not be processed: unknown
	// format, unreadable/malformed manifest (parse.ClassParseFailed).
	FailureTarget
	// FailureInternal means an unexpected internal error in the parser,
	// matcher or database layer — distinct from bad user input.
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
	return f.Class.String() + ": " + f.Target.Key() + ": " + f.Err.Error()
}

func (f Failure) Unwrap() error { return f.Err }

// Target names one manifest file and the parser format to use.
type Target struct {
	Format string
	Path   string
}

// Key is the deterministic cache key of a target.
func (t Target) Key() string { return t.Format + ":" + t.Path }

// Result is the per-target scan outcome. When Failure != nil the scan did not
// pass: Findings/Manifest belong to a failed attempt and must not be treated
// as a clean conclusion. Rejected/Warning counts are carried so even a
// successful parse with refused records stays visible.
type Result struct {
	Target Target
	// DBRevision embeds the exact vulnerability-database snapshot used, so a
	// historical conclusion can be reproduced after the rules file changes.
	DBRevision string
	Manifest   *component.Manifest
	Findings   []match.Finding
	Failure    *Failure
}

// OK reports whether the target was scanned without failure. A successful
// scan may still carry findings (vulnerabilities) or rejected records.
func (r *Result) OK() bool { return r != nil && r.Failure == nil }

// Scanner scans single targets.
type Scanner struct {
	db *vulndb.Database
}

// New creates a Scanner bound to db.
func New(db *vulndb.Database) *Scanner { return &Scanner{db: db} }

// Scan parses and matches one target. It always returns a Result; failures are
// carried in-band as Result.Failure instead of panicking or being swallowed.
func (s *Scanner) Scan(ctx context.Context, t Target) (result *Result) {
	result = &Result{Target: t}
	defer func() {
		if r := recover(); r != nil {
			result = &Result{
				Target: t,
				Failure: &Failure{Class: FailureInternal, Target: t,
					Err: fmt.Errorf("panic: %v", r)},
			}
		}
	}()

	if s.db == nil {
		result.Failure = &Failure{Class: FailureInternal, Target: t, Err: fmt.Errorf("nil vulnerability database")}
		return result
	}
	result.DBRevision = s.db.Revision
	p := parse.Get(t.Format)
	if p == nil {
		result.Failure = &Failure{Class: FailureTarget, Target: t,
			Err: fmt.Errorf("unknown format %q (registered: %v)", t.Format, parse.Formats())}
		return result
	}

	m, err := p.Parse(ctx, t.Path)
	if err != nil {
		fc := FailureTarget
		var pe *parse.Error
		if errors.As(err, &pe) && pe.Class == parse.ClassInternal {
			fc = FailureInternal
		}
		result.Failure = &Failure{Class: fc, Target: t, Err: err}
		return result
	}

	found, err := match.New(s.db).Match(m)
	if err != nil {
		result.Failure = &Failure{Class: FailureInternal, Target: t, Err: err}
		return result
	}

	result.Manifest = m
	result.Findings = found
	return result
}
