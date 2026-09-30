package vuln

import (
	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
)

// AffectedRange 描述单个受影响区间（affected）与修复边界（fixed）。
type AffectedRange struct {
	// Introduced 为该区间引入版本；空串或 "0" 表示从 0.0.0 开始。
	Introduced string
	// Fixed 为修复版本；空串表示尚未修复（区间无上界）。
	// fixed 边界本身不计为受影响（[introduced, fixed) 左闭右开）。
	Fixed string
}

// Advisory 是本地漏洞库中的一条漏洞规则。
type Advisory struct {
	ID          string
	Ecosystem   component.Ecosystem
	PackageName string
	// Summary 为人类可读的漏洞摘要。
	Summary string
	// Ranges 为多个受影响区间的并集。
	Ranges []AffectedRange
}

// Match 记录一个成分命中一条漏洞的可解释结论。
type Match struct {
	Component component.Component
	Advisory  Advisory
	// MatchedRange 是命中的那个区间，便于解释边界。
	MatchedRange AffectedRange
}
