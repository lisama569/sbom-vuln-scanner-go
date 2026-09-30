package semver

import "fmt"

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

// Bound is one comparison boundary.
type Bound struct {
	Op Operator
	V  Version
}

func (b Bound) String() string { return string(b.Op) + b.V.String() }

// Constraint is a union of intersections of bounds (OR of AND groups), e.g.
// ">=1.0.0 <1.5.0 || >=2.0.0 <2.1.0".
type Constraint struct {
	Groups [][]Bound
	raw    string
}

// Raw returns the original constraint text.
func (c Constraint) Raw() string { return c.raw }

func (c Constraint) String() string { return c.raw }

// ParseConstraint parses a constraint expression.
func ParseConstraint(s string) (Constraint, error) {
	return Constraint{}, fmt.Errorf("semver: not implemented")
}

// Contains reports whether v satisfies the constraint.
func (c Constraint) Contains(v Version) bool { return false }

// FixedVersion is an advisory's "fixed in" declaration: versions >= V are no
// longer vulnerable (handled as a < V upper bound for the affected range).
type FixedVersion struct {
	V Version
}
