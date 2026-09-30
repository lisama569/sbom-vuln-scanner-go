package manifest

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/semver"
)

// GoModParser 解析 go.mod（require 块中的直接/间接依赖）。
type GoModParser struct{}

func (p GoModParser) Format() string { return "go.mod" }

func (p GoModParser) MatchNames(fileName string) bool {
	return filepath.Base(fileName) == "go.mod"
}

func (p GoModParser) Parse(fileName string, data []byte) (*component.ParseResult, error) {
	res := &component.ParseResult{Format: p.Format(), File: fileName}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024*16)

	inRequire := false
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(stripGoComment(raw))

		if line == "" {
			continue
		}
		if !inRequire && strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		var spec string
		switch {
		case inRequire:
			spec = line
		case strings.HasPrefix(line, "require ") && !strings.Contains(line, "("):
			spec = strings.TrimSpace(strings.TrimPrefix(line, "require"))
		default:
			continue
		}
		p.requireEntry(fileName, lineNo, raw, spec, res)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 go.mod 行失败: %w", err)
	}
	return res, nil
}

func (p GoModParser) requireEntry(fileName string, lineNo int, raw, spec string, res *component.ParseResult) {
	fields := strings.Fields(spec)
	relation := component.RelationDirect
	// 检查原始行中的注释（stripGoComment 已去掉，改在注释剥离前判断）。
	if strings.Contains(raw, "//") {
		comment := raw[strings.Index(raw, "//")+2:]
		if strings.Contains(strings.TrimSpace(comment), "indirect") {
			relation = component.RelationIndirect
		}
	}
	switch {
	case len(fields) == 0:
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: raw,
			Code: component.IssueMalformedEntry, Message: "require 条目为空",
		})
	case len(fields) < 2:
		code := component.IssueMissingField
		msg := fmt.Sprintf("require 条目缺少版本: %q", fields[0])
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: raw, Code: code, Message: msg,
		})
	default:
		name, version := fields[0], strings.TrimSuffix(fields[1], "//")
		version = strings.TrimSpace(version)
		if name == "" {
			res.Issues = append(res.Issues, component.ParseIssue{
				File: fileName, Line: lineNo, Raw: raw,
				Code: component.IssueMissingField, Message: "require 条目缺少包名",
			})
			return
		}
		if _, err := semver.Parse(version); err != nil {
			res.Issues = append(res.Issues, component.ParseIssue{
				File: fileName, Line: lineNo, Raw: raw,
				Code:    component.IssueInvalidVersion,
				Message: fmt.Sprintf("依赖 %s 的版本 %q 非法: %v", name, version, err),
			})
			return
		}
		res.Components = append(res.Components, component.Component{
			Ecosystem:  component.EcoGoModules,
			Name:       name,
			Version:    version,
			Relation:   relation,
			SourceFile: fileName,
		})
	}
}

// stripGoComment 去掉 // 行注释（保留原始行中的注释信息需在调用处另行处理，
// 因此这里仅用于结构判断前的裁剪；indirect 判定使用未裁剪的 raw）。
func stripGoComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}
