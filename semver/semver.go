// Package semver implements semantic version parsing, comparison and
// constraint/range evaluation used by vulnerability matching.
//
// Versions follow https://semver.org with a leading "v" tolerated:
//
//	MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
//
// Pre-release versions have lower precedence than the associated release, per
// the semver spec. Build metadata is ignored in comparisons.
package semver

import "fmt"

// Version is a parsed semantic version.
type Version struct {
	Major, Minor, Patch int64
	Pre                 []preIdent
	pre                 string // raw pre-release, without leading '-'
	build               string
	raw                 string
}

type preIdent struct {
	numeric bool
	num     int64
	str     string
}

// String returns the canonical form of the version.
func (v Version) String() string {
	return v.raw
}

// Parse parses a semantic version string.
func Parse(s string) (Version, error) { return Version{}, fmt.Errorf("semver: not implemented") }

// Compare returns -1, 0, 1 comparing precedence of v and o.
func (v Version) Compare(o Version) int { return 0 }

// IsPrerelease reports whether the version carries pre-release metadata.
func (v Version) IsPrerelease() bool { return false }
