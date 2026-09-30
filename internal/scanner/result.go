package scanner

import (
	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/vuln"
)

// TargetStatus 是单个目标的扫描结论状态。
type TargetStatus string

const (
	// StatusOK 扫描完成：无漏洞、无被拒绝条目。
	StatusOK TargetStatus = "ok"
	// StatusVuln 扫描完成且存在漏洞命中。
	StatusVuln TargetStatus = "vulnerable"
	// StatusRejected 扫描完成但存在被拒绝/无法扫描的畸形条目。
	StatusRejected TargetStatus = "rejected"
	// StatusFailed 该目标自身失败（文件/格式/解析器错误），结论无效。
	StatusFailed TargetStatus = "failed"
)

// TargetResult 是单个目标的完整结论。
type TargetResult struct {
	Path       string
	Format     string
	Status     TargetStatus
	Components []component.Component
	Matches    []vuln.Match
	Issues     []component.ParseIssue
	Err        *ScanError
	// DBRevision 记录扫描时使用的漏洞库版本，支持历史结论复现。
	DBRevision string
	// CacheHit 标记结论来自缓存（仅用于可观测性，不改变结论）。
	CacheHit bool
}

// HasVulnerabilities 报告该目标是否存在命中。
func (r *TargetResult) HasVulnerabilities() bool { return len(r.Matches) > 0 }

// HasRejectedIssues 报告是否存在导致条目无法被扫描的拒绝级问题。
func (r *TargetResult) HasRejectedIssues() bool {
	for _, is := range r.Issues {
		if component.SeverityOf(is.Code) == component.SeverityRejected {
			return true
		}
	}
	return false
}

// Report 是多目标并发扫描的汇总。
type Report struct {
	Results  []*TargetResult
	Revision string
	// Fatal 为非 nil 时表示整体扫描因致命错误中止。
	Fatal *ScanError
}

// Passed 仅当无致命错误、无失败目标、无漏洞命中、无拒绝级问题时才为 true。
// 即：部分失败不能当成整体通过。
func (r *Report) Passed() bool {
	if r.Fatal != nil {
		return false
	}
	for _, t := range r.Results {
		if t.Status == StatusFailed || t.HasVulnerabilities() || t.HasRejectedIssues() {
			return false
		}
	}
	return true
}

// VulnerableCount 返回所有目标中去重前的命中总数（同一目标内部已由 Matcher 去重）。
func (r *Report) VulnerableCount() int {
	n := 0
	for _, t := range r.Results {
		n += len(t.Matches)
	}
	return n
}
