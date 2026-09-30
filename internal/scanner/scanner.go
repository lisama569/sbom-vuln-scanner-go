// Package scanner 并发扫描多个本地清单目标，做成分归一化、漏洞匹配与结果缓存。
package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/manifest"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/vuln"
)

// Options 控制扫描并发度与缓存开关。
type Options struct {
	Concurrency int
	UseCache    bool
}

// Scanner 组合解析注册表、漏洞匹配器与结果缓存。
type Scanner struct {
	registry *manifest.Registry
	matcher  *vuln.Matcher
	cache    *resultCache
	opts     Options
}

// New 创建扫描器；db 为 nil 属于致命配置错误。
func New(db vuln.Database, opts Options) (*Scanner, error) {
	if db == nil {
		return nil, &ScanError{Kind: KindFatal, Err: fmt.Errorf("漏洞库未初始化")}
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	return &Scanner{
		registry: manifest.NewRegistry(),
		matcher:  vuln.NewMatcher(db),
		cache:    newResultCache(),
		opts:     opts,
	}, nil
}

// Registry 暴露解析注册表（便于测试注入自定义解析器）。
func (s *Scanner) Registry() *manifest.Registry { return s.registry }

// CacheStats 返回缓存命中/未命中次数，用于测试与日志验证。
func (s *Scanner) CacheStats() (hits, misses int) { return s.cache.stats() }

// ScanOne 扫描单个目标。任何情况都返回非 nil 的 TargetResult，
// 错误被分类后写入结果，绝不 panic、绝不影响其它目标。
func (s *Scanner) ScanOne(ctx context.Context, path string) *TargetResult {
	result := &TargetResult{Path: path, DBRevision: s.matcher.Revision()}

	// 1. 读取文件（文件不存在/不可读 => 目标失败）。
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		result.Status = StatusFailed
		result.Err = &ScanError{Kind: KindTargetFailure, Target: path, Err: readErr}
		return result
	}
	key := cacheKey{path: path, fileHash: hashBytes(data), dbRevision: result.DBRevision}
	if s.opts.UseCache {
		if cached, ok := s.cache.get(key); ok {
			cached.CacheHit = true
			return cached
		}
	}

	// 2. 选择解析器（不支持的格式 => 目标失败，区别于解析器内部报错）。
	parser := s.registry.ParserFor(path)
	if parser == nil {
		result.Status = StatusFailed
		result.Err = &ScanError{
			Kind:   KindTargetFailure,
			Target: path,
			Err: &component.ParseIssue{
				File: path, Code: component.IssueUnsupportedFile,
				Message: fmt.Sprintf("不支持的清单格式: %s", path),
			},
		}
		s.store(key, result)
		return result
	}

	// 3. 解析；解析器内部错误（JSON 结构性损坏等）与单条警告严格区分。
	pr, parseErr := parser.Parse(path, data)
	if parseErr != nil {
		result.Status = StatusFailed
		result.Err = &ScanError{Kind: KindParseError, Target: path, Err: parseErr}
		s.store(key, result)
		return result
	}
	result.Format = pr.Format
	result.Issues = pr.Issues

	// 4. 确定性合并同一依赖的重复出现。
	result.Components = MergeComponents(pr.Components)

	// 5. 对每个成分做漏洞匹配；单个成分版本非法不会中止整个目标。
	for _, c := range result.Components {
		if err := ctx.Err(); err != nil {
			result.Status = StatusFailed
			result.Err = &ScanError{Kind: KindTargetFailure, Target: path, Err: err}
			return result
		}
		matches, err := s.matcher.Match(c)
		if err != nil {
			// 归一化后的成分版本理论上已校验过；走到这里属于匹配器内部错误。
			result.Status = StatusFailed
			result.Err = &ScanError{Kind: KindParseError, Target: path, Err: err}
			s.store(key, result)
			return result
		}
		result.Matches = append(result.Matches, matches...)
	}

	switch {
	case result.HasVulnerabilities():
		result.Status = StatusVuln
	case result.HasRejectedIssues():
		result.Status = StatusRejected
	default:
		result.Status = StatusOK
	}
	s.store(key, result)
	return result
}

func (s *Scanner) store(k cacheKey, r *TargetResult) {
	if s.opts.UseCache {
		// 缓存存一份不含 CacheHit 标记的副本。
		cp := *r
		cp.CacheHit = false
		s.cache.put(k, &cp)
	}
}

// Scan 并发扫描多个目标。
//
// 并发只改变完成先后，不改变最终结论：返回结果严格按输入路径顺序排列；
// 单个目标的任何错误都被隔离在自己的 TargetResult 中；
// 一个目标的异常不会污染其它目标的成分或命中结果。
func (s *Scanner) Scan(ctx context.Context, paths []string) *Report {
	report := &Report{Revision: s.matcher.Revision(), Results: make([]*TargetResult, len(paths))}

	sem := make(chan struct{}, s.opts.Concurrency)
	var wg sync.WaitGroup
	for i, path := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					// 防御性：解析库 panic 归类为解析器内部错误，绝不炸掉整个批次。
					report.Results[idx] = &TargetResult{
						Path:       p,
						Status:     StatusFailed,
						DBRevision: report.Revision,
						Err: &ScanError{
							Kind:   KindParseError,
							Target: p,
							Err:    fmt.Errorf("解析器内部 panic: %v", rec),
						},
					}
				}
			}()
			report.Results[idx] = s.ScanOne(ctx, p)
		}(i, path)
	}
	wg.Wait()
	return report
}
