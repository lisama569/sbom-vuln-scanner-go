package scanner

import (
	"context"
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/vuln"
)

// TestE2ESamplesRepro 使用仓库自带的漏洞库与样例清单，验证：
// 1) 并发扫描的结论可以逐依赖、逐漏洞条目解释；
// 2) 同一份清单重复扫描结论完全一致（历史可复现）；
// 3) 第二轮全部走缓存，命中数不随并发顺序变化。
func TestE2ESamplesRepro(t *testing.T) {
	db, err := vuln.LoadDatabase(vuln.LoadOptions{Directory: "../../testdata/advisories"})
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{
		"../../testdata/samples/go.mod",
		"../../testdata/samples/package-lock.json",
		"../../testdata/samples/requirements.txt",
	}

	s, _ := New(db, Options{Concurrency: 4, UseCache: true})
	first := s.Scan(context.Background(), targets)
	second := s.Scan(context.Background(), targets)
	third := s.Scan(context.Background(), targets)

	sig1 := reportSignature(first)
	sig2 := reportSignature(second)
	sig3 := reportSignature(third)
	t.Logf("第1轮签名:\n%s", sig1)
	if sig1 != sig2 || sig2 != sig3 {
		t.Fatalf("三轮扫描结论不一致:\n%s\n---\n%s\n---\n%s", sig1, sig2, sig3)
	}
	for _, r := range first.Results {
		for _, m := range r.Matches {
			t.Logf("判定依据: %s | %s/%s@%s 命中 %s [%s,%s)",
				r.Path, m.Component.Ecosystem, m.Component.Name, m.Component.Version,
				m.Advisory.ID, or0(m.MatchedRange.Introduced), orEmpty(m.MatchedRange.Fixed))
		}
		for _, is := range r.Issues {
			t.Logf("判定依据: %s | 问题[%s/%s] %s", r.Path, is.Code, is.Message, is.Raw)
		}
	}
	if first.VulnerableCount() != 5 {
		t.Fatalf("样例命中数=%d 期望 5", first.VulnerableCount())
	}
	hits, misses := s.CacheStats()
	t.Logf("缓存统计: 命中=%d 未命中=%d（3 目标 x 3 轮，后两轮 6 次应全部命中）", hits, misses)
	if misses != 3 || hits != 6 {
		t.Fatalf("缓存命中/未命中 = %d/%d 期望 6/3", hits, misses)
	}
	for _, r := range second.Results {
		if !r.CacheHit {
			t.Fatalf("第二轮目标 %s 未命中缓存", r.Path)
		}
	}
	if first.Passed() {
		t.Fatal("样例含漏洞与拒绝级条目，不应通过")
	}
}

func reportSignature(r *Report) string {
	b := make([]byte, 0, 256)
	b = append(b, "rev="+r.Revision+"\n"...)
	for _, t := range r.Results {
		b = append(b, ("T:" + t.Path + ":" + string(t.Status) + "\n")...)
		for _, m := range t.Matches {
			b = append(b, ("  M:" + m.Advisory.ID + ":" + m.Component.Name + "@" + m.Component.Version + "\n")...)
		}
		for _, is := range t.Issues {
			b = append(b, ("  I:" + string(is.Code) + ":" + is.Raw + "\n")...)
		}
	}
	return string(b)
}

func or0(s string) string {
	if s == "" {
		return "0.0.0"
	}
	return s
}
func orEmpty(s string) string {
	if s == "" {
		return "未修复"
	}
	return s
}
