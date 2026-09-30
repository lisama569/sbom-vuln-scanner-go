package manifest

import (
	"strings"
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
)

func TestGoModMalformed(t *testing.T) {
	src := `module example.com/x

require example.com/good v1.2.3
require example.com/dup v1.0.0
require example.com/dup v1.0.0 // indirect
require example.com/badver v1.2
require example.com/nover
require (
	example.com/ind v0.9.0 // indirect
)
`
	p := GoModParser{}
	res, err := p.Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("非预期内部错误: %v", err)
	}
	t.Logf("原始清单:\n%s", src)
	for _, c := range res.Components {
		t.Logf("归一化成分: %s %s@%s relation=%s", c.Ecosystem, c.Name, c.Version, c.Relation)
	}
	for _, is := range res.Issues {
		t.Logf("问题[%s]: %s", is.Code, is.Error())
	}
	if len(res.Components) != 4 { // good / dup / ind，dup 去重在 scanner；这里解析层保留 4 条
		t.Errorf("归一化成分数=%d 期望 4（解析层不合并）", len(res.Components))
	}
	codes := issueCodes(res)
	if !hasCode(codes, component.IssueInvalidVersion) {
		t.Errorf("期望 invalid_version，实际 %v", codes)
	}
	if !hasCode(codes, component.IssueMissingField) {
		t.Errorf("期望 missing_field，实际 %v", codes)
	}
}

func TestNpmLockMalformed(t *testing.T) {
	src := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"version": "1.0.0"},
    "node_modules/ok-pkg": {"version": "1.2.3"},
    "node_modules/no-ver": {},
    "node_modules/bad-ver": {"version": "01.2.3"},
    "node_modules/a/node_modules/nested": {"version": "3.0.0"}
  }
}`
	p := NpmLockParser{}
	res, err := p.Parse("package-lock.json", []byte(src))
	if err != nil {
		t.Fatalf("非预期内部错误: %v", err)
	}
	t.Logf("原始清单: %s", src)
	for _, c := range res.Components {
		t.Logf("归一化成分: %s %s@%s relation=%s", c.Ecosystem, c.Name, c.Version, c.Relation)
	}
	for _, is := range res.Issues {
		t.Logf("问题[%s]: %s", is.Code, is.Error())
	}
	if len(res.Components) != 2 {
		t.Errorf("归一化成分数=%d 期望 2", len(res.Components))
	}
	// nested 位于二级 node_modules，必须是间接。
	for _, c := range res.Components {
		if c.Name == "nested" && c.Relation != component.RelationIndirect {
			t.Errorf("nested 应为 indirect，实际 %s", c.Relation)
		}
	}
	codes := issueCodes(res)
	if !hasCode(codes, component.IssueMissingField) || !hasCode(codes, component.IssueInvalidVersion) {
		t.Errorf("期望 missing_field+invalid_version，实际 %v", codes)
	}

	// 结构性损坏的 JSON 必须返回解析器内部 error，与单条问题区分。
	if _, err := p.Parse("package-lock.json", []byte("{not json")); err == nil {
		t.Errorf("损坏 JSON 应返回内部错误")
	} else {
		t.Logf("结构性错误被区分为: %v", err)
	}
}

func TestRequirementsMalformed(t *testing.T) {
	src := strings.Join([]string{
		"requests-like==2.20.3",
		"flask>=2.0",
		"six",
		"urllib3==1.26.15 ; python_version < \"3.10\"",
		"-r dev-requirements.txt",
		"bad==1.2",
	}, "\n")
	p := RequirementsParser{}
	res, err := p.Parse("requirements.txt", []byte(src))
	if err != nil {
		t.Fatalf("非预期内部错误: %v", err)
	}
	t.Logf("原始清单:\n%s", src)
	for _, c := range res.Components {
		t.Logf("归一化成分: %s %s@%s relation=%s", c.Ecosystem, c.Name, c.Version, c.Relation)
	}
	for _, is := range res.Issues {
		t.Logf("问题[%s/%s]: %s", component.SeverityOf(is.Code), is.Code, is.Error())
	}
	if len(res.Components) != 2 { // requests-like + urllib3
		t.Errorf("归一化成分数=%d 期望 2", len(res.Components))
	}
	codes := issueCodes(res)
	for _, want := range []component.IssueCode{
		component.IssueNonPinnedSpecifier, component.IssueMissingField,
		component.IssueEnvMarker, component.IssueDirective, component.IssueInvalidVersion,
	} {
		if !hasCode(codes, want) {
			t.Errorf("期望问题代码 %s，实际 %v", want, codes)
		}
	}
}

func TestRegistryUnsupported(t *testing.T) {
	r := NewRegistry()
	if _, err := r.ReadAndParse("nonexistent/pom.xml"); err == nil {
		t.Errorf("不支持的文件应返回错误")
	} else {
		t.Logf("不支持格式被区分: %v", err)
	}
}

func issueCodes(res *component.ParseResult) []component.IssueCode {
	out := make([]component.IssueCode, 0, len(res.Issues))
	for _, is := range res.Issues {
		out = append(out, is.Code)
	}
	return out
}

func hasCode(codes []component.IssueCode, want component.IssueCode) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}
