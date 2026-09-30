package semver

import "testing"

func TestParseInvalid(t *testing.T) {
	bad := []string{
		"", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03",
		"1.2.3-", "1.2.3-alpha..1", "1.2.3-01", "v", "1.2.x", "latest",
	}
	for _, in := range bad {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) 期望非法错误，却解析成功", in)
		} else {
			t.Logf("原始输入 %q => 拒绝原因: %v", in, err)
		}
	}
}

func TestParseValid(t *testing.T) {
	ok := []string{"0.0.0", "v1.2.3", "V1.2.3", "1.5.0-rc.1", "2.0.0-alpha.1", "1.0.0+build.42"}
	for _, in := range ok {
		v, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q) 非预期错误: %v", in, err)
			continue
		}
		t.Logf("原始输入 %q => 归一化: major=%d minor=%d patch=%d prerelease=%v",
			in, v.Major, v.Minor, v.Patch, v.Prerelease)
	}
}

func TestComparePrerelease(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0-alpha", "1.0.0", -1}, // 预发布 < 正式
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1}, // 数字 < 字母数字
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-rc.1", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.5.0", "1.5.0", 0},
	}
	for _, c := range cases {
		va, _ := Parse(c.a)
		vb, _ := Parse(c.b)
		if got := Compare(va, vb); got != c.want {
			t.Errorf("Compare(%q,%q)=%d 期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRangeBoundaries(t *testing.T) {
	// 漏洞库 affected 区间 [1.0.0, 1.5.0) 的等价约束。
	r, err := ParseRange(">=1.0.0 <1.5.0")
	if err != nil {
		t.Fatalf("ParseRange: %v", err)
	}
	cases := []struct {
		v    string
		want bool
	}{
		{"0.9.9", false},
		{"1.0.0", true}, // introduced 边界包含
		{"1.4.9", true},
		{"1.5.0-rc.1", true}, // 预发布 < fixed，仍受影响
		{"1.5.0", false},     // fixed 边界不包含：已修复
		{"1.5.1", false},
		{"2.0.0", false},
	}
	for _, c := range cases {
		v, _ := Parse(c.v)
		got := r.Contains(v)
		t.Logf("判定依据: 版本 %q 落在区间 %q ? %v (期望 %v)", c.v, r.Original, got, c.want)
		if got != c.want {
			t.Errorf("Contains(%q)=%v 期望 %v", c.v, got, c.want)
		}
	}
}

func TestUnionConstraint(t *testing.T) {
	// 多区间并集：[1.0.0,1.2.0) || [2.0.0,2.1.0)
	cs, err := ParseConstraint(">=1.0.0 <1.2.0 || >=2.0.0 <2.1.0")
	if err != nil {
		t.Fatalf("ParseConstraint: %v", err)
	}
	cases := []struct {
		v    string
		want bool
	}{
		{"1.1.9", true},
		{"1.2.0", false}, // 落在并集空洞里
		{"1.5.0", false},
		{"2.0.0", true},
		{"2.1.0", false},
	}
	for _, c := range cases {
		v, _ := Parse(c.v)
		got := cs.Contains(v)
		t.Logf("判定依据: 版本 %q 命中并集 %q ? %v", c.v, cs.Original, got)
		if got != c.want {
			t.Errorf("union Contains(%q)=%v 期望 %v", c.v, got, c.want)
		}
	}
}

func TestMalformedConstraint(t *testing.T) {
	for _, in := range []string{"", ">=1.2", "~1.2.3", ">= 1.0.0 ||", "==abc"} {
		if _, err := ParseConstraint(in); err == nil {
			t.Errorf("约束 %q 应解析失败", in)
		} else {
			t.Logf("原始区间 %q => 拒绝: %v", in, err)
		}
	}
}
