package component

import "fmt"

// Ecosystem 标识依赖所属的包管理生态。
type Ecosystem string

const (
	EcoGoModules Ecosystem = "go"
	EcoNpm       Ecosystem = "npm"
	EcoPypi      Ecosystem = "pypi"
)

// Relation 表示依赖与根清单之间的关系。
type Relation string

const (
	RelationDirect   Relation = "direct"
	RelationIndirect Relation = "indirect"
)

// Component 是从各种清单归一化得到的统一成分模型。
type Component struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
	Relation  Relation
	// SourceFile 记录成分来自哪个清单文件，便于溯源。
	SourceFile string
}

// Key 返回成分的稳定唯一键（生态 + 名称，版本不参与，
// 因为同一依赖不同出现处需要按键合并）。
func (c Component) Key() string {
	return string(c.Ecosystem) + "://" + c.Name
}

// IssueCode 标识清单解析期间的问题类别。
type IssueCode string

const (
	IssueInvalidVersion  IssueCode = "invalid_version"
	IssueMissingField    IssueCode = "missing_field"
	IssueMalformedEntry  IssueCode = "malformed_entry"
	IssueUnsupportedFile IssueCode = "unsupported_file"
)

// ParseIssue 记录一条不能被静默跳过的解析问题。
type ParseIssue struct {
	File    string
	Line    int
	Raw     string
	Code    IssueCode
	Message string
}

func (i ParseIssue) Error() string {
	if i.Line > 0 {
		return fmt.Sprintf("%s:%d [%s] %s (原始输入: %q)", i.File, i.Line, i.Code, i.Message, i.Raw)
	}
	return fmt.Sprintf("%s [%s] %s (原始输入: %q)", i.File, i.Code, i.Message, i.Raw)
}

// ParseResult 是单个清单文件的解析结论。
type ParseResult struct {
	Components []Component
	Issues     []ParseIssue
	Format     string
	File       string
}
