package semver

import "testing"

func TestConstraintContains(t *testing.T) {
	cases := []struct {
		expr string
		ver  string
		want bool
	}{
		// Single closed interval boundary semantics.
		{">=1.0.0 <1.5.0", "1.0.0", true},   // lower inclusive
		{">=1.0.0 <1.5.0", "1.4.9", true},
		{">=1.0.0 <1.5.0", "1.5.0", false},  // upper exclusive
		{">=1.0.0 <1.5.0", "0.9.9", false},
		// Pre-release participates by pure precedence.
		{">=1.0.0 <1.5.0", "1.5.0-alpha", true},
		{">=1.0.0 <1.5.0", "1.0.0-alpha", false}, // < 1.0.0
		// Glued operator.
		{">=1.0.0<1.5.0", "1.2.0", false}, // treated as one malformed token? see below
		{"!=1.0.0", "1.0.0", false},
		{"!=1.0.0", "1.0.1", true},
		// Bare version = exact.
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
		// Union of intervals.
		{">=1.0.0 <1.5.0 || >=2.0.0 <2.1.0", "1.4.0", true},
		{">=1.0.0 <1.5.0 || >=2.0.0 <2.1.0", "1.6.0", false},
		{">=1.0.0 <1.5.0 || >=2.0.0 <2.1.0", "2.0.0", true},
		{">=1.0.0 <1.5.0 || >=2.0.0 <2.1.0", "2.1.0", false},
		{">=1.0.0 <1.5.0 || >=2.0.0 <2.1.0", "2.1.0-rc.1", true},
	}
	for _, c := range cases {
		con, err := ParseConstraint(c.expr)
		if err != nil {
			// The glued-without-space invalid case is expected to fail parsing.
			if c.ver == "1.2.0" && c.expr == ">=1.0.0<1.5.0" {
				t.Logf("raw expr %q -> parse error as expected: %v", c.expr, err)
				continue
			}
			t.Fatalf("ParseConstraint(%q): %v", c.expr, err)
		}
		v, err := Parse(c.ver)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.ver, err)
		}
		got := con.Contains(v)
		t.Logf("expr=%-32q ver=%-12q => %v", c.expr, c.ver, got)
		if got != c.want {
			t.Errorf("Contains(%q in %q)=%v want %v", c.ver, c.expr, got, c.want)
		}
	}
}

func TestConstraintInvalid(t *testing.T) {
	for _, expr := range []string{"", "||", ">= ", "~1.0.0", ">=notaver", "1.0.0 ||", ">=1.0.0 <"} {
		if _, err := ParseConstraint(expr); err == nil {
			t.Errorf("ParseConstraint(%q) expected error", expr)
		} else {
			t.Logf("raw expr %q -> reject: %v", expr, err)
		}
	}
}
