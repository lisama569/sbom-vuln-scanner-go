package semver

import (
	"fmt"
	"regexp"
	"strings"
)

// Operator is a constraint boundary operator.
type Operator string

const (
	OpEq  Operator = "="
	OpNe  Operator = "!="
	OpGt  Operator = ">"
	OpGte Operator = ">="
	OpLt  Operator = "<"
	OpLte Operator = "<="
)

func validOp(op string) bool {
	switch Operator(op) {
	case OpEq, OpNe, OpGt, OpGte, OpLt, OpLte:
		return true
	}
	return false
}

// Bound is one comparison boundary.
type Bound struct {
	Op Operator
	V  Version
}

func (b Bound) String() string { return string(b.Op) + b.V.String() }

// Holds reports whether version v satisfies this single boundary.
func (b Bound) Holds(v Version) bool {
	c := v.Compare(b.V)
	switch b.Op {
	case OpEq:
		return c == 0
	case OpNe:
		return c != 0
	case OpGt:
		return c > 0
	case OpGte:
		return c >= 0
	case OpLt:
		return c < 0
	case OpLte:
		return c <= 0
	default:
		return false
	}
}

// Constraint is a union of intersections of bounds (OR of AND groups), e.g.
// ">=1.0.0 <1.5.0 || >=2.0.0 <2.1.0".
type Constraint struct {
	Groups [][]Bound
	raw    string
}

// Raw returns the original constraint text.
func (c Constraint) Raw() string { return c.raw }

func (c Constraint) String() string { return c.raw }

// opPrefix matches an operator glued directly to a version token.
var opPrefix = regexp.MustCompile(`^(>=|<=|!=|>|<|=)(.+)$`)

// ParseConstraint parses a constraint expression.
//
// Grammar:
//
//	constraint  = group { "||" group }
//	group       = bound { whitespace bound }
//	bound       = [op] version        # missing op means "="
//	op          = "=" | "!=" | ">" | ">=" | "<" | "<="
//
// Bounds inside a group are AND-ed; groups are OR-ed. Versions use the same
// rules as Parse. Pre-release versions participate purely by semver
// precedence, e.g. 1.5.0-alpha < 1.5.0, so it falls inside ">=1.0.0 <1.5.0".
func ParseConstraint(s string) (Constraint, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Constraint{}, fmt.Errorf("empty constraint")
	}
	parts := strings.Split(raw, "||")
	c := Constraint{raw: raw}
	for gi, part := range parts {
		group, err := parseGroup(strings.TrimSpace(part))
		if err != nil {
			return Constraint{}, fmt.Errorf("constraint %q group #%d: %w", s, gi+1, err)
		}
		c.Groups = append(c.Groups, group)
	}
	return c, nil
}

func parseGroup(g string) ([]Bound, error) {
	if g == "" {
		return nil, fmt.Errorf("empty range group")
	}
	fields := strings.Fields(g)
	var bounds []Bound
	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		op := ""
		verText := tok
		// Operator glued to version: ">=1.0.0".
		if m := opPrefix.FindStringSubmatch(tok); m != nil {
			op = m[1]
			verText = m[2]
		} else if validOp(tok) {
			// Operator as its own token; version follows.
			if i+1 >= len(fields) {
				return nil, fmt.Errorf("operator %q has no version", tok)
			}
			op = tok
			i++
			verText = fields[i]
		}
		if op != "" && !validOp(op) {
			return nil, fmt.Errorf("unknown operator %q", op)
		}
		v, err := Parse(verText)
		if err != nil {
			return nil, err
		}
		if op == "" {
			op = "="
		}
		bounds = append(bounds, Bound{Op: Operator(op), V: v})
	}
	if len(bounds) == 0 {
		return nil, fmt.Errorf("group has no bounds")
	}
	return bounds, nil
}

// Contains reports whether v satisfies the constraint.
func (c Constraint) Contains(v Version) bool {
	_, ok := c.MatchingGroup(v)
	return ok
}

// MatchingGroup returns the index of the first AND group all of whose bounds
// hold for v. The index enables explainable match output.
func (c Constraint) MatchingGroup(v Version) (int, bool) {
	for gi, group := range c.Groups {
		all := true
		for _, b := range group {
			if !b.Holds(v) {
				all = false
				break
			}
		}
		if all {
			return gi, true
		}
	}
	return -1, false
}
