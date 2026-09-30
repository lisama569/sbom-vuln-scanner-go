package scanner

import (
	"sort"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
)

// MergeComponents 对同一清单内重复出现的依赖给出确定性结论：
//
// 合并键为 (生态, 名称, 版本)：
//   - 同一依赖以相同版本在直接依赖与传递依赖中重复出现时，
//     合并为一条，关系取“直接”优先（direct > indirect），来源保留首次出现；
//   - 同名但不同版本（典型为 npm 嵌套 node_modules 中的多版本副本）
//     不予合并，各自保留为独立成分，避免漏报其中任一版本；
//   - 输出按 Key()（生态、名称、版本、关系）排序，保证顺序与文件遍历顺序无关。
func MergeComponents(cs []component.Component) []component.Component {
	type merged struct {
		c     component.Component
		order int
	}
	index := make(map[string]*merged)
	keys := make([]string, 0)
	order := 0
	for _, c := range cs {
		dk := dedupKey(c)
		if m, ok := index[dk]; ok {
			// 关系升级：直接优先于传递。
			if c.Relation == component.RelationDirect && m.c.Relation != component.RelationDirect {
				m.c.Relation = component.RelationDirect
			}
			continue
		}
		index[dk] = &merged{c: c, order: order}
		keys = append(keys, dk)
		order++
	}
	out := make([]component.Component, 0, len(keys))
	for _, k := range keys {
		out = append(out, index[k].c)
	}
	sort.Slice(out, func(i, j int) bool {
		return stableKey(out[i]) < stableKey(out[j])
	})
	return out
}

func dedupKey(c component.Component) string {
	return string(c.Ecosystem) + "://" + c.Name + "@" + c.Version
}

// stableKey 仅在去重键相同时不会被用到；它额外带上关系与来源用于稳定排序。
func stableKey(c component.Component) string {
	return dedupKey(c) + "|" + string(c.Relation) + "|" + c.SourceFile
}
