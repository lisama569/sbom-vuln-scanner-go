package vuln

import (
	"fmt"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/semver"
)

// Matcher 基于漏洞库对成分做版本区间匹配。
type Matcher struct {
	db Database
}

// NewMatcher 创建匹配器。
func NewMatcher(db Database) *Matcher { return &Matcher{db: db} }

// Match 对单个成分做匹配，返回去重后的命中列表。
//
// 区间语义（稳定且可解释）：
//   - 单个 affected 区间为 [introduced, fixed)：introduced 边界包含，fixed 边界不包含；
//   - introduced 为空或 "0" 表示从 0.0.0 起；fixed 为空表示尚未修复（无上界）；
//   - 多个 affected 区间取并集；
//   - 预发布版本按 semver 优先级比较，例如 fixed=1.5.0 时，1.5.0-rc.1 仍命中，
//     因为 1.5.0-rc.1 < 1.5.0（尚未达到修复版本）。
//
// 同一 advisory 最多产生一条 Match，杜绝重复计数。
func (m *Matcher) Match(c component.Component) ([]Match, error) {
	ver, err := semver.Parse(c.Version)
	if err != nil {
		return nil, fmt.Errorf("成分 %s(%s) 版本非法: %w", c.Name, c.Version, err)
	}
	advisories := m.db.Lookup(c.Ecosystem, c.Name)
	matches := make([]Match, 0)
	seen := make(map[string]struct{})
	for _, adv := range advisories {
		if _, dup := seen[adv.ID]; dup {
			continue
		}
		for _, ar := range adv.Ranges {
			hit, err := rangeContains(ar, ver)
			if err != nil {
				return nil, fmt.Errorf("漏洞 %s 的区间规则非法: %w", adv.ID, err)
			}
			if hit {
				matches = append(matches, Match{Component: c, Advisory: adv, MatchedRange: ar})
				seen[adv.ID] = struct{}{}
				break // 并集命中一次即可
			}
		}
	}
	return matches, nil
}

// rangeContains 判定 v 是否落在 [introduced, fixed) 内。
func rangeContains(ar AffectedRange, v semver.Version) (bool, error) {
	intro := ar.Introduced
	if intro == "" || intro == "0" {
		intro = "0.0.0"
	}
	iv, err := semver.Parse(intro)
	if err != nil {
		return false, err
	}
	if semver.Compare(v, iv) < 0 {
		return false, nil
	}
	if ar.Fixed == "" {
		return true, nil
	}
	fv, err := semver.Parse(ar.Fixed)
	if err != nil {
		return false, err
	}
	// fixed 边界不包含：v < fixed 才算受影响。
	return semver.Compare(v, fv) < 0, nil
}

func (m Match) Key() string {
	return m.Advisory.ID + "@" + string(m.Component.Ecosystem) + "://" + m.Component.Name + "@" + m.Component.Version
}

// Revision 返回匹配器使用的漏洞库版本。
func (m *Matcher) Revision() string { return m.db.Revision() }
