// Package gomod parses Go go.mod files.
package gomod

import (
	"context"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
)

// Parser implements parse.Parser for go.mod.
type Parser struct{}

// New returns a new go.mod parser.
func New() *Parser { return &Parser{} }

func (Parser) Format() string { return "gomod" }

// Parse reads and normalizes a go.mod file.
//
// All require entries are ScopeDirect by convention (go.mod does not carry
// transitive pins). Version strings must be canonical semver with an optional
// leading "v"; major-version suffixes such as "/v2" are part of the module
// path and preserved in the component name.
func (Parser) Parse(ctx context.Context, path string) (*component.Manifest, error) {
	return nil, &parse.Error{Class: parse.ClassInternal, Format: "gomod", Path: path, Err: errNotImplemented}
}

var errNotImplemented = stubErr("gomod: not implemented")

type stubErr string

func (e stubErr) Error() string { return string(e) }

var _ component.Component
