package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/scanner"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/vuln"
)

func main() {
	dbDir := flag.String("db", "testdata/advisories", "本地漏洞库目录")
	concurrency := flag.Int("concurrency", 4, "并发扫描目标数")
	noCache := flag.Bool("no-cache", false, "关闭结果缓存")
	repeat := flag.Int("repeat", 1, "整批重复扫描次数（用于验证缓存与结论稳定性）")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s [选项] <清单文件>...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	targets := flag.Args()
	if len(targets) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	db, err := vuln.LoadDatabase(vuln.LoadOptions{Directory: *dbDir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "致命错误: 加载漏洞库失败: %v\n", err)
		os.Exit(3)
	}

	s, err := scanner.New(db, scanner.Options{
		Concurrency: *concurrency,
		UseCache:    !*noCache,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "致命错误: %v\n", err)
		os.Exit(3)
	}

	var report *scanner.Report
	for i := 0; i < *repeat; i++ {
		report = s.Scan(context.Background(), targets)
	}
	hits, misses := s.CacheStats()
	printReport(report, hits, misses)

	if report.Fatal != nil {
		os.Exit(3)
	}
	if !report.Passed() {
		os.Exit(1)
	}
}

func printReport(r *scanner.Report, cacheHits, cacheMisses int) {
	fmt.Printf("漏洞库版本(rev): %s\n", r.Revision)
	fmt.Printf("缓存命中: %d 未命中: %d\n", cacheHits, cacheMisses)
	for _, t := range r.Results {
		fmt.Printf("\n=== 目标 %s [格式=%s 状态=%s 缓存=%v] ===\n",
			t.Path, t.Format, t.Status, t.CacheHit)
		for _, is := range t.Issues {
			level := "警告"
			if component.SeverityOf(is.Code) == component.SeverityRejected {
				level = "拒绝"
			}
			fmt.Printf("  [%s/%s] %s\n", level, is.Code, is.Error())
		}
		if t.Err != nil {
			fmt.Printf("  错误[%s]: %v\n", t.Err.Kind, t.Err)
		}
		for _, m := range t.Matches {
			c := m.Component
			ar := m.MatchedRange
			intro := ar.Introduced
			if intro == "" {
				intro = "0.0.0"
			}
			fixed := ar.Fixed
			if fixed == "" {
				fixed = "未修复"
			}
			fmt.Printf("  漏洞 %s: %s/%s@%s (%s) 命中区间 [%s, %s) — %s\n",
				m.Advisory.ID, c.Ecosystem, c.Name, c.Version, c.Relation,
				intro, fixed, m.Advisory.Summary)
		}
		if len(t.Matches) == 0 && t.Err == nil && len(t.Issues) == 0 {
			fmt.Printf("  无漏洞命中，共 %d 个成分\n", len(t.Components))
		}
	}
	fmt.Printf("\n结论: %d 个目标, %d 条漏洞命中, 通过=%v\n",
		len(r.Results), r.VulnerableCount(), r.Passed())
}
