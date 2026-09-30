package vuln

import (
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
)

// fakeDB 是确定性的内存漏洞库，不依赖磁盘。
type fakeDB struct {
	data     map[string][]Advisory
	revision string
}

func (d *fakeDB) Lookup(eco component.Ecosystem, name string) []Advisory {
	return d.data[string(eco)+"://"+name]
}
func (d *fakeDB) Revision() string { return d.revision }

func newFakeDB(rev string, advs ...Advisory) *fakeDB {
	d := &fakeDB{data: map[string][]Advisory{}, revision: rev}
	for _, a := range advs {
		k := string(a.Ecosystem) + "://" + a.PackageName
		d.data[k] = append(d.data[k], a)
	}
	return d
}

func comp(name, ver string, rel component.Relation) component.Component {
	return component.Component{Ecosystem: component.EcoGoModules, Name: name, Version: ver,
		Relation: rel, SourceFile: "go.mod"}
}

func TestMatcherBoundaries(t *testing.T) {
	db := newFakeDB("rev-1",
		Advisory{ID: "A-1", Ecosystem: component.EcoGoModules, PackageName: "p",
			Ranges: []AffectedRange{{Introduced: "1.0.0", Fixed: "1.5.0"}}},
		Advisory{ID: "A-2", Ecosystem: component.EcoGoModules, PackageName: "p",
			Ranges: []AffectedRange{
				{Introduced: "2.0.0", Fixed: "2.1.0"},
				{Introduced: "2.2.0", Fixed: ""}, // 无修复上界
			}},
	)
	m := NewMatcher(db)
	cases := []struct {
		ver  string
		want []string
	}{
		{"0.9.9", nil},
		{"1.0.0", []string{"A-1"}}, // introduced 边界包含
		{"1.4.0", []string{"A-1"}},
		{"1.5.0-rc.1", []string{"A-1"}}, // 预发布尚未达到修复版本
		{"1.5.0", nil},                  // fixed 边界不包含
		{"2.0.0", []string{"A-2"}},
		{"2.1.0", nil}, // 第一段上界，且第二段尚未开始
		{"2.2.0", []string{"A-2"}},
		{"9.9.9", []string{"A-2"}}, // open-ended
	}
	for _, c := range cases {
		got, err := m.Match(comp("p", c.ver, component.RelationDirect))
		if err != nil {
			t.Fatalf("Match(%s) 非预期错误: %v", c.ver, err)
		}
		ids := make([]string, 0, len(got))
		for _, mt := range got {
			ids = append(ids, mt.Advisory.ID)
		}
		t.Logf("判定依据: p@%s 命中 %v（区间 [intro=%s, fixed=%q)），期望 %v",
			c.ver, ids, gotRangeIntro(got), gotRangeFixed(got), c.want)
		if !equalSet(ids, c.want) {
			t.Errorf("p@%s 命中 %v 期望 %v", c.ver, ids, c.want)
		}
	}
}

func gotRangeIntro(ms []Match) string {
	if len(ms) == 0 {
		return "-"
	}
	return ms[0].MatchedRange.Introduced
}
func gotRangeFixed(ms []Match) string {
	if len(ms) == 0 {
		return "-"
	}
	return ms[0].MatchedRange.Fixed
}

func TestMatcherNoDoubleCount(t *testing.T) {
	// 两条区间重叠，同一条 advisory 只能计数一次。
	db := newFakeDB("rev-2",
		Advisory{ID: "DUP", Ecosystem: component.EcoGoModules, PackageName: "p",
			Ranges: []AffectedRange{
				{Introduced: "1.0.0", Fixed: "2.0.0"},
				{Introduced: "1.5.0", Fixed: "3.0.0"},
			}},
	)
	m := NewMatcher(db)
	got, err := m.Match(comp("p", "1.8.0", component.RelationDirect))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("原始输入: 2 个重叠区间；归一化命中数=%d（期望 1，不重复计数）", len(got))
	if len(got) != 1 || got[0].Advisory.ID != "DUP" {
		t.Fatalf("重叠区间被重复计数: %+v", got)
	}
}

func TestMatcherInvalidVersion(t *testing.T) {
	db := newFakeDB("rev-3")
	m := NewMatcher(db)
	if _, err := m.Match(comp("p", "not-a-version", component.RelationDirect)); err == nil {
		t.Errorf("非法版本应返回错误以区分")
	} else {
		t.Logf("非法版本被区分: %v", err)
	}
}

func TestLoadDatabaseRevision(t *testing.T) {
	// 直接使用仓库内样例库，验证 revision 可重复计算。
	d1, err := LoadDatabase(LoadOptions{Directory: "../../testdata/advisories"})
	if err != nil {
		t.Fatalf("加载漏洞库失败: %v", err)
	}
	d2, err := LoadDatabase(LoadOptions{Directory: "../../testdata/advisories"})
	if err != nil {
		t.Fatal(err)
	}
	if d1.Revision() == "" || d1.Revision() != d2.Revision() {
		t.Fatalf("revision 不稳定: %q vs %q", d1.Revision(), d2.Revision())
	}
	t.Logf("漏洞库内容版本: %s（重复加载一致 => 历史结论可复现）", d1.Revision())
	if got := d1.Lookup(component.EcoNpm, "left-pad-lite"); len(got) != 1 {
		t.Fatalf("left-pad-lite 规则数=%d 期望 1", len(got))
	}
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, v := range seen {
		if v != 0 {
			return false
		}
	}
	return true
}
