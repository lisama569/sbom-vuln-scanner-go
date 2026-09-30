// Package npm parses npm package-lock.json files (lockfileVersion 2/3).
package npm

import (
	"context"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
)

// Parser implements parse.Parser for package-lock.json.
type Parser struct{}

// New returns a new npm lockfile parser.
func New() *Parser { return &Parser{} }

func (Parser) Format() string { return "npm" }

// Parse reads and normalizes a package-lock.json.
//
// Direct deps come from packages[""].dependencies/devDependencies; every
// other packages/* entry is transitive. A package appearing both directly and
// transitively is resolved once as direct (documented dedup rule).
func (Parser) Parse(ctx context.Context, path string) (*component.Manifest, error) {
	return nil, &parse.Error{Class: parse.ClassInternal, Format: "npm", Path: path, Err: errNotImplemented}
}

var errNotImplemented = stubErr("npm: not implemented")

type stubErr string

func (e stubErr) Error() string { return string(e) }

var _ component.Component
