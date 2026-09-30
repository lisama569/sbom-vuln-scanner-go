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

// RequirementsParser 解析 requirements.txt（pip）。
// 支持的可归一子集：name[extras]==version（含 ; 环境标记，标记记警告）。
type RequirementsParser struct{}

func (p RequirementsParser) Format() string { return "requirements.txt" }

func (p RequirementsParser) MatchNames(fileName string) bool {
	base := filepath.Base(fileName)
	if base == "requirements.txt" {
		return true
	}
	return strings.HasPrefix(base, "requirements") && filepath.Ext(base) == ".txt"
}

func (p RequirementsParser) Parse(fileName string, data []byte) (*component.ParseResult, error) {
	res := &component.ParseResult{Format: p.Format(), File: fileName}

	// 合并反斜杠续行，同时保留起始行号。
	var lines []string
	var lineNos []int
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024*16)
	lineNo := 0
	var pending string
	pendingStart := 0
	for sc.Scan() {
		lineNo++
		cur := sc.Text()
		if strings.HasSuffix(strings.TrimSpace(cur), "\\") {
			if pending == "" {
				pendingStart = lineNo
			}
			pending += strings.TrimSuffix(strings.TrimSpace(cur), "\\")
			continue
		}
		if pending != "" {
			cur = pending + strings.TrimSpace(cur)
			lineNo = pendingStart
			pending = ""
		}
		lines = append(lines, cur)
		lineNos = append(lineNos, lineNo)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取 requirements.txt 行失败: %w", err)
	}
	if pending != "" {
		lines = append(lines, pending)
		lineNos = append(lineNos, pendingStart)
	}

	for i, raw := range lines {
		p.parseLine(fileName, lineNos[i], raw, res)
	}
	return res, nil
}

func (p RequirementsParser) parseLine(fileName string, lineNo int, rawLine string, res *component.ParseResult) {
	raw := strings.TrimSpace(rawLine)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return
	}
	// 去掉行内注释。
	if i := strings.Index(raw, " #"); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}

	// pip 指令行（-r/-c/-e/-f/--hash 等）不当作依赖静默吞掉。
	if strings.HasPrefix(raw, "-") {
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: rawLine,
			Code:    component.IssueDirective,
			Message: fmt.Sprintf("pip 指令行不是可归一的依赖条目: %q", firstField(raw)),
		})
		return
	}

	// 环境标记。
	marker := ""
	body := raw
	if i := strings.Index(body, ";"); i >= 0 {
		marker = strings.TrimSpace(body[i+1:])
		body = strings.TrimSpace(body[:i])
	}

	// 分离 name[extras] 与版本说明符。
	namePart, spec, hasSpec := cutSpec(body)
	name := stripExtras(strings.TrimSpace(namePart))
	if name == "" {
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: rawLine,
			Code:    component.IssueMalformedEntry,
			Message: "无法从条目解析出包名",
		})
		return
	}
	if !hasSpec {
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: rawLine,
			Code:    component.IssueMissingField,
			Message: fmt.Sprintf("依赖 %s 未钉选版本（缺少 ==version）", name),
		})
		return
	}

	op, ver, err := splitSpec(spec)
	if err != nil {
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: rawLine,
			Code:    component.IssueNonPinnedSpecifier,
			Message: fmt.Sprintf("依赖 %s 的版本说明符无法归一为确定版本: %v", name, err),
		})
		return
	}
	if op != "==" {
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: rawLine,
			Code:    component.IssueNonPinnedSpecifier,
			Message: fmt.Sprintf("依赖 %s 使用非钉选算子 %q（仅 == 可确定唯一成分版本）", name, op),
		})
		return
	}
	if _, err := semver.Parse(ver); err != nil {
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: rawLine,
			Code:    component.IssueInvalidVersion,
			Message: fmt.Sprintf("依赖 %s 的版本 %q 非法: %v", name, ver, err),
		})
		return
	}

	c := component.Component{
		Ecosystem:  component.EcoPypi,
		Name:       name,
		Version:    ver,
		Relation:   component.RelationDirect,
		SourceFile: fileName,
	}
	res.Components = append(res.Components, c)
	if marker != "" {
		// 结构合法但生效条件依赖环境：保留成分并给出可区分警告。
		res.Issues = append(res.Issues, component.ParseIssue{
			File: fileName, Line: lineNo, Raw: rawLine,
			Code:    component.IssueEnvMarker,
			Message: fmt.Sprintf("依赖 %s 带环境标记 %q，是否实际安装取决于目标环境", name, marker),
		})
	}
}

// cutSpec 在第一个版本算子（==,>=,<=,~=,!=,>,<,=）处切分包名与说明符。
func cutSpec(s string) (name, spec string, ok bool) {
	for _, op := range []string{"==", ">=", "<=", "~=", "!=", ">", "<", "="} {
		if i := strings.Index(s, op); i >= 0 {
			return s[:i], strings.TrimSpace(s[i:]), true
		}
	}
	return s, "", false
}

func splitSpec(spec string) (op, ver string, err error) {
	for _, op := range []string{"==", ">=", "<=", "~=", "!=", ">", "<", "="} {
		if strings.HasPrefix(spec, op) {
			v := strings.TrimSpace(strings.TrimPrefix(spec, op))
			if v == "" {
				return "", "", fmt.Errorf("算子 %s 后缺少版本", op)
			}
			return op, v, nil
		}
	}
	return "", "", fmt.Errorf("无法识别的版本说明符 %q", spec)
}

func stripExtras(name string) string {
	if i := strings.Index(name, "["); i >= 0 {
		return strings.TrimSpace(name[:i])
	}
	return name
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return s
}
