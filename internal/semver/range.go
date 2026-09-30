package semver

import (
	"fmt"
	"strings"
)

// ComparatorOp 是区间比较算子。
type ComparatorOp string

const (
	OpGTE ComparatorOp = ">="
	OpGT  ComparatorOp = ">"
	OpLTE ComparatorOp = "<="
	OpLT  ComparatorOp = "<"
	OpEQ  ComparatorOp = "="
)

// Comparator 是单个比较条件。
type Comparator struct {
	Op      ComparatorOp
	Version Version
}

// Contains 判断版本是否满足单个比较条件。
func (c Comparator) Contains(v Version) bool {
	cmp := Compare(v, c.Version)
	switch c.Op {
	case OpGTE:
		return cmp >= 0
	case OpGT:
		return cmp > 0
	case OpLTE:
		return cmp <= 0
	case OpLT:
		return cmp < 0
	case OpEQ:
		return cmp == 0
	default:
		return false
	}
}

// Range 是多个比较条件的交集（AND）。
type Range struct {
	Comparators []Comparator
	Original    string
}

// Contains 判断版本是否落在区间内（所有比较条件同时满足）。
func (r Range) Contains(v Version) bool {
	for _, c := range r.Comparators {
		if !c.Contains(v) {
			return false
		}
	}
	return true
}

// ParseRange 解析形如 ">=1.2.0 <2.0.0" 的单个区间（比较条件的交集）。
// 裸版本号 "1.2.3" 按精确匹配 "=1.2.3" 处理。
func ParseRange(s string) (Range, error) {
	orig := s
	s = strings.TrimSpace(s)
	if s == "" {
		return Range{}, fmt.Errorf("空区间表达式")
	}
	fields := strings.Fields(s)
	comps := make([]Comparator, 0, len(fields))
	for _, f := range fields {
		c, err := parseComparator(f)
		if err != nil {
			return Range{}, fmt.Errorf("区间 %q: %w", orig, err)
		}
		comps = append(comps, c)
	}
	return Range{Comparators: comps, Original: orig}, nil
}

func parseComparator(tok string) (Comparator, error) {
	var op ComparatorOp
	rest := tok
	switch {
	case strings.HasPrefix(tok, ">="):
		op, rest = OpGTE, strings.TrimSpace(tok[2:])
	case strings.HasPrefix(tok, "<="):
		op, rest = OpLTE, strings.TrimSpace(tok[2:])
	case strings.HasPrefix(tok, ">"):
		op, rest = OpGT, strings.TrimSpace(tok[1:])
	case strings.HasPrefix(tok, "<"):
		op, rest = OpLT, strings.TrimSpace(tok[1:])
	case strings.HasPrefix(tok, "="):
		op, rest = OpEQ, strings.TrimSpace(tok[1:])
	default:
		op = OpEQ
	}
	v, err := Parse(rest)
	if err != nil {
		return Comparator{}, fmt.Errorf("比较式 %q: %w", tok, err)
	}
	return Comparator{Op: op, Version: v}, nil
}

// Constraint 是多个区间的并集（OR）。
type Constraint struct {
	Ranges   []Range
	Original string
}

// ParseConstraint 解析形如 ">=1.0.0 <1.5.0 || >=2.0.0 <2.1.0" 的多区间并集。
func ParseConstraint(s string) (Constraint, error) {
	orig := s
	parts := strings.Split(s, "||")
	ranges := make([]Range, 0, len(parts))
	for _, p := range parts {
		r, err := ParseRange(p)
		if err != nil {
			return Constraint{}, fmt.Errorf("约束 %q: %w", orig, err)
		}
		ranges = append(ranges, r)
	}
	return Constraint{Ranges: ranges, Original: orig}, nil
}

// Contains 判断版本是否命中任一区间（并集）。
func (c Constraint) Contains(v Version) bool {
	for _, r := range c.Ranges {
		if r.Contains(v) {
			return true
		}
	}
	return false
}
