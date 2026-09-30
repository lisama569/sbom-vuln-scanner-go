// Package manifest 负责解析多种依赖清单/锁文件并归一到统一成分模型。
package manifest

import (
	"fmt"
	"os"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
)

// Parser 解析一种清单格式。
type Parser interface {
	// Format 返回格式标识。
	Format() string
	// MatchNames 判断文件名是否属于该格式。
	MatchNames(fileName string) bool
	// Parse 解析原始字节。
	// 单条记录的问题（缺字段、版本非法、结构不完整）必须写入
	// ParseResult.Issues 而非静默跳过；只有解析器自身的内部错误才返回 error。
	Parse(fileName string, data []byte) (*component.ParseResult, error)
}

// Registry 按文件名选择解析器。
type Registry struct {
	parsers []Parser
}

// NewRegistry 创建内置格式齐全的注册表。
func NewRegistry() *Registry {
	r := &Registry{}
	r.Register(GoModParser{})
	r.Register(NpmLockParser{})
	r.Register(RequirementsParser{})
	return r
}

func (r *Registry) Register(p Parser) { r.parsers = append(r.parsers, p) }

// ParserFor 返回匹配文件名的解析器，没有则 nil。
func (r *Registry) ParserFor(fileName string) Parser {
	for _, p := range r.parsers {
		if p.MatchNames(fileName) {
			return p
		}
	}
	return nil
}

// ReadAndParse 读取文件并选用合适解析器解析。
// 不支持的文件返回带 IssueUnsupportedFile 的错误，供上层归类为目标失败。
func (r *Registry) ReadAndParse(path string) (*component.ParseResult, error) {
	p := r.ParserFor(path)
	if p == nil {
		return nil, &component.ParseIssue{
			File:    path,
			Code:    component.IssueUnsupportedFile,
			Message: fmt.Sprintf("不支持的清单格式: %s", path),
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res, err := p.Parse(path, data)
	if err != nil {
		return nil, err
	}
	return res, nil
}
