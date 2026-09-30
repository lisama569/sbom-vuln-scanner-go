// Package parse defines the manifest parser interface, error classification
// and the parser registry shared by concrete format parsers.
package parse

import (
	"context"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
)

// ErrorClass categorizes a parser failure.
type ErrorClass int

const (
	// ClassOK means no error.
	ClassOK ErrorClass = iota
	// ClassParseFailed means the input is malformed and could not be read at
	// all as the claimed format (fatal for that single target).
	ClassParseFailed
	// ClassInternal means the parser itself errored unexpectedly (fatal,
	// distinct from bad input).
	ClassInternal
)

func (c ErrorClass) String() string {
	switch c {
	case ClassParseFailed:
		return "parse_failed"
	case ClassInternal:
		return "internal"
	default:
		return "ok"
	}
}

// Error wraps a parser error with its class.
type Error struct {
	Class  ErrorClass
	Format string
	Path   string
	Err    error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Class.String() + ": " + e.Format + " " + e.Path + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Parser parses one manifest/lock file into a normalized component.Manifest.
//
// Implementations must not silently drop malformed records: they go into
// Manifest.Rejected with a distinguishable reason. Structural failures that
// prevent parsing entirely return a *parse.Error.
type Parser interface {
	Format() string
	Parse(ctx context.Context, path string) (*component.Manifest, error)
}

var registry = map[string]Parser{}

// Register makes a parser available by format name.
func Register(p Parser) { registry[p.Format()] = p }

// Get returns the parser registered for format, or nil.
func Get(format string) Parser { return registry[format] }

// Formats returns registered format names.
func Formats() []string {
	out := make([]string, 0, len(registry))
	for f := range registry {
		out = append(out, f)
	}
	return out
}
