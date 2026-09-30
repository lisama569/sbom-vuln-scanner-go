// Package semver 实现语义化版本解析、比较以及预发布版本的稳定判定。
package semver

import (
	"fmt"
	"strconv"
	"strings"
)

// Version 是解析后的语义化版本。
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease []string
	Original   string
}

// Parse 严格按 https://semver.org 解析版本（允许可选的 "v" 前缀）。
// 非法版本返回错误，调用方据此区分“版本非法”与“未命中”。
func Parse(s string) (Version, error) {
	orig := s
	if s == "" {
		return Version{}, fmt.Errorf("空版本号")
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	// 剥离 build metadata（比较时忽略，但保留对其基本格式的校验）。
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if i == len(s)-1 {
			return Version{}, fmt.Errorf("版本 %q 的 build metadata 为空", orig)
		}
		s = s[:i]
	}

	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
		if pre == "" {
			return Version{}, fmt.Errorf("版本 %q 的预发布后缀为空", orig)
		}
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("版本 %q 不是 MAJOR.MINOR.PATCH 三段形式", orig)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := parseNumericIdent(p)
		if err != nil {
			return Version{}, fmt.Errorf("版本 %q: %w", orig, err)
		}
		nums[i] = n
	}

	v := Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Original: orig}
	if pre != "" {
		for _, ident := range strings.Split(pre, ".") {
			if !isValidIdent(ident) {
				return Version{}, fmt.Errorf("版本 %q 的预发布标识符 %q 非法", orig, ident)
			}
			if _, err := strconv.Atoi(ident); err == nil {
				// 纯数字标识符已在 isValidIdent 中禁止前导零。
			}
		}
		v.Prerelease = strings.Split(pre, ".")
	}
	return v, nil
}

func parseNumericIdent(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("数字段为空")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("数字段 %q 含前导零", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("数字段 %q 非法", s)
	}
	return n, nil
}

func isValidIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'z') &&
			!(r >= 'A' && r <= 'Z') && r != '-' {
			return false
		}
	}
	if _, err := strconv.Atoi(s); err == nil && len(s) > 1 && s[0] == '0' {
		return false
	}
	return true
}

// Compare 按 semver 规范比较两个版本，返回 -1 / 0 / 1。
// 预发布版本优先级低于同主.次.修订号的正式版本，例如 1.0.0-alpha < 1.0.0。
func Compare(a, b Version) int {
	if c := cmpInt(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpInt(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpInt(a.Patch, b.Patch); c != 0 {
		return c
	}
	return comparePrerelease(a.Prerelease, b.Prerelease)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func comparePrerelease(a, b []string) int {
	// 两者都无预发布：相等。
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	// 有预发布的优先级更低。
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := compareIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func compareIdent(x, y string) int {
	xn, xErr := strconv.Atoi(x)
	yn, yErr := strconv.Atoi(y)
	switch {
	case xErr == nil && yErr == nil:
		return cmpInt(xn, yn)
	case xErr == nil:
		// 数字标识符优先级低于字母数字标识符。
		return -1
	case yErr == nil:
		return 1
	default:
		return strings.Compare(x, y)
	}
}

func (v Version) String() string { return v.Original }

// IsPrerelease 判断是否为预发布版本。
func (v Version) IsPrerelease() bool { return len(v.Prerelease) > 0 }
