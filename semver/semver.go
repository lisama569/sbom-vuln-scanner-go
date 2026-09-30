// Package semver implements semantic version parsing, comparison and
// constraint/range evaluation used by vulnerability matching.
//
// Versions follow https://semver.org with a leading "v"/"V" tolerated:
//
//	MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
//
// Pre-release versions have lower precedence than the associated release, per
// the semver spec. Build metadata is ignored in comparisons.
package semver

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed semantic version.
type Version struct {
	Major, Minor, Patch int64
	// Pre holds the ordered pre-release identifiers; empty for a release.
	Pre []preIdent
	raw string
}

type preIdent struct {
	numeric bool
	num     int64
	str     string
}

// Raw returns the trimmed input the version was parsed from (without leading v).
func (v Version) Raw() string { return v.raw }

// String returns the canonical form of the version.
func (v Version) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d.%d.%d", v.Major, v.Minor, v.Patch)
	if len(v.Pre) > 0 {
		b.WriteByte('-')
		for i, p := range v.Pre {
			if i > 0 {
				b.WriteByte('.')
			}
			if p.numeric {
				b.WriteString(strconv.FormatInt(p.num, 10))
			} else {
				b.WriteString(p.str)
			}
		}
	}
	return b.String()
}

// Parse parses a semantic version string.
func Parse(s string) (Version, error) {
	in := strings.TrimSpace(s)
	orig := in
	if in == "" {
		return Version{}, fmt.Errorf("empty version %q", s)
	}
	if in[0] == 'v' || in[0] == 'V' {
		in = in[1:]
	}
	if in == "" {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}

	// Build metadata: ignored for precedence but still validated.
	if i := strings.IndexByte(in, '+'); i >= 0 {
		build := in[i+1:]
		in = in[:i]
		if err := validateIdentList(build, true); err != nil {
			return Version{}, fmt.Errorf("invalid version %q: bad build metadata: %w", s, err)
		}
	}

	// Pre-release.
	pre := ""
	if i := strings.IndexByte(in, '-'); i >= 0 {
		pre = in[i+1:]
		in = in[:i]
		if err := validateIdentList(pre, false); err != nil {
			return Version{}, fmt.Errorf("invalid version %q: bad prerelease: %w", s, err)
		}
	}

	core := strings.Split(in, ".")
	if len(core) != 3 {
		return Version{}, fmt.Errorf("invalid version %q: core must be MAJOR.MINOR.PATCH", s)
	}
	nums := make([]int64, 3)
	for i, p := range core {
		n, err := parseNumericIdent(p)
		if err != nil {
			return Version{}, fmt.Errorf("invalid version %q: %w", s, err)
		}
		nums[i] = n
	}

	v := Version{Major: nums[0], Minor: nums[1], Patch: nums[2], raw: orig}
	if pre != "" {
		for _, id := range strings.Split(pre, ".") {
			if n, err := strconv.ParseInt(id, 10, 64); err == nil {
				v.Pre = append(v.Pre, preIdent{numeric: true, num: n})
			} else {
				v.Pre = append(v.Pre, preIdent{str: id})
			}
		}
	}
	return v, nil
}

// validateIdentList validates a dot separated list of numeric or alphanumeric
// identifiers per semver §9/§10. Numeric identifiers must not have leading
// zeroes. When allowNumeric is false (build metadata the rule is actually the
// same; build identifiers are never parsed as numbers).
func validateIdentList(list string, build bool) error {
	if list == "" {
		return fmt.Errorf("empty identifier")
	}
	for _, id := range strings.Split(list, ".") {
		if id == "" {
			return fmt.Errorf("empty identifier")
		}
		numeric := true
		for _, r := range id {
			if r < '0' || r > '9' {
				numeric = false
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
					return fmt.Errorf("illegal character %q in identifier %q", r, id)
				}
			}
		}
		if numeric {
			if _, err := parseNumericIdent(id); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseNumericIdent parses a non-negative numeric identifier, rejecting
// leading zeroes ("01") per the semver spec.
func parseNumericIdent(id string) (int64, error) {
	if id == "" {
		return 0, fmt.Errorf("empty numeric identifier")
	}
	if len(id) > 1 && id[0] == '0' {
		return 0, fmt.Errorf("numeric identifier %q has leading zero", id)
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("non-numeric identifier %q", id)
	}
	return n, nil
}

// Compare returns -1, 0, 1 comparing precedence of v and o.
func (v Version) Compare(o Version) int {
	if c := cmpInt64(v.Major, o.Major); c != 0 {
		return c
	}
	if c := cmpInt64(v.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmpInt64(v.Patch, o.Patch); c != 0 {
		return c
	}
	return comparePre(v.Pre, o.Pre)
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// comparePre implements semver §11 precedence of pre-release identifiers.
// A version without pre-release has higher precedence than one with.
func comparePre(a, b []preIdent) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1 // release > prerelease
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		switch {
		case x.numeric && !y.numeric:
			return -1 // numeric < alphanumeric
		case !x.numeric && y.numeric:
			return 1
		case x.numeric && y.numeric:
			if c := cmpInt64(x.num, y.num); c != 0 {
				return c
			}
		default:
			if c := strings.Compare(x.str, y.str); c != 0 {
				return c
			}
		}
	}
	return cmpInt64(int64(len(a)), int64(len(b)))
}

// IsPrerelease reports whether the version carries pre-release metadata.
func (v Version) IsPrerelease() bool { return len(v.Pre) > 0 }

// Eq reports equal precedence.
func (v Version) Eq(o Version) bool { return v.Compare(o) == 0 }
