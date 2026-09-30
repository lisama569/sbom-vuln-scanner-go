package manifest

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/semver"
)

// NpmLockParser 解析 package-lock.json v2/v3。
type NpmLockParser struct{}

func (p NpmLockParser) Format() string { return "package-lock.json" }

func (p NpmLockParser) MatchNames(fileName string) bool {
	return filepath.Base(fileName) == "package-lock.json"
}

type npmLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
}

type npmLockPackage struct {
	Version string `json:"version"`
	// dev/optional/peer 标记不影响其作为成分被归一化（均纳入扫描）。
	Dev      bool `json:"dev"`
	Optional bool `json:"optional"`
}

func (p NpmLockParser) Parse(fileName string, data []byte) (*component.ParseResult, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		// 结构性 JSON 错误属于解析器内部错误。
		return nil, fmt.Errorf("package-lock.json 结构非法: %w", err)
	}
	if len(lock.Packages) == 0 {
		return nil, fmt.Errorf("package-lock.json 缺少 packages 映射（仅支持 lockfileVersion 2/3）")
	}
	res := &component.ParseResult{Format: p.Format(), File: fileName}

	// 按 key 排序保证输出确定性。
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		pkg := lock.Packages[key]
		// key == "" 是根项目自身，不是依赖成分。
		if key == "" {
			continue
		}
		name := npmPackageName(key)
		raw := fmt.Sprintf(`%q: {"version": %q}`, key, pkg.Version)
		if name == "" {
			res.Issues = append(res.Issues, component.ParseIssue{
				File: fileName, Raw: raw,
				Code:    component.IssueMalformedEntry,
				Message: fmt.Sprintf("packages 节点 %q 无法解析出包名", key),
			})
			continue
		}
		if strings.TrimSpace(pkg.Version) == "" {
			res.Issues = append(res.Issues, component.ParseIssue{
				File: fileName, Raw: raw,
				Code:    component.IssueMissingField,
				Message: fmt.Sprintf("npm 包 %s 缺少 version 字段", name),
			})
			continue
		}
		if _, err := semver.Parse(pkg.Version); err != nil {
			res.Issues = append(res.Issues, component.ParseIssue{
				File: fileName, Raw: raw,
				Code:    component.IssueInvalidVersion,
				Message: fmt.Sprintf("npm 包 %s 的版本 %q 非法: %v", name, pkg.Version, err),
			})
			continue
		}
		relation := component.RelationIndirect
		if isDirectNpmNode(key) {
			relation = component.RelationDirect
		}
		res.Components = append(res.Components, component.Component{
			Ecosystem:  component.EcoNpm,
			Name:       name,
			Version:    pkg.Version,
			Relation:   relation,
			SourceFile: fileName,
		})
	}
	return res, nil
}

// npmPackageName 从 packages 映射的 key 提取实际包名，
// 处理 scoped 包（@scope/name）与嵌套 node_modules。
func npmPackageName(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	if idx < 0 {
		// v3 根节点有时直接以包名为 key。
		return strings.TrimSpace(key)
	}
	name := key[idx+len("node_modules/"):]
	if name == "" || name == "." || strings.ContainsAny(name, `{}"`) {
		return ""
	}
	return name
}

// isDirectNpmNode 判断节点是否为顶层直接依赖：
// 形如 "node_modules/xxx"（路径中只有一个 node_modules 段）。
func isDirectNpmNode(key string) bool {
	rest := strings.TrimPrefix(key, "node_modules/")
	return rest != key && !strings.Contains(rest, "node_modules/")
}
