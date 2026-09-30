package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/internal/component"
	"github.com/lisama569/sbom-vuln-scanner-go/internal/vuln"
)

func testDB(rev string) vuln.Database {
	return vuln.MustNewFakeDB(rev, []vuln.Advisory{
		{ID: "V-1", Ecosystem: component.EcoGoModules, PackageName: "example.com/v",
			Summary: "test vuln", Ranges: []vuln.AffectedRange{{Introduced: "1.0.0", Fixed: "2.0.0"}}},
	})
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const goModGood = `module x
go 1.25
require example.com/v v1.5.0
require example.com/safe v1.0.0
`

const goModDup = `module x
go 1.25
require example.com/v v1.5.0
require example.com/v v1.5.0 // indirect
`

const goModBad = `module x
go 1.25
require example.com/v v1.2
`

func TestScanDedupAndDeterministic(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "go.mod", goModDup)
	s, err := New(testDB("r1"), Options{Concurrency: 4, UseCache: false})
	if err != nil {
		t.Fatal(err)
	}
	r1 := s.ScanOne(context.Background(), f)
	r2 := s.ScanOne(context.Background(), f)
	t.Logf("原始输入:\n%s", goModDup)
	for _, c := range r1.Components {
		t.Logf("归一化判定依据: %s@%s relation=%s（同包同版本直接+间接重复 => 合并为一条且直接优先）",
			c.Name, c.Version, c.Relation)
	}
	if len(r1.Components) != 1 {
		t.Fatalf("成分数=%d 期望 1（重复的 v 合并为一条）", len(r1.Components))
	}
	for _, c := range r1.Components {
		if c.Name == "example.com/v" && c.Relation != component.RelationDirect {
			t.Errorf("重复出现后关系应升级为 direct，实际 %s", c.Relation)
		}
	}
	if len(r1.Matches) != len(r2.Matches) {
		t.Fatal("重复扫描命中数不稳定")
	}
	// 多轮并发顺序随机化，最终结果必须一致。
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := s.ScanOne(context.Background(), f)
			if len(r.Matches) != 1 || len(r.Components) != 1 {
				t.Errorf("并发扫描结论漂移: matches=%d comps=%d", len(r.Matches), len(r.Components))
			}
		}()
	}
	wg.Wait()
}

func TestCacheHitAndInvalidation(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "go.mod", goModGood)
	s, _ := New(testDB("r1"), Options{Concurrency: 2, UseCache: true})

	first := s.ScanOne(context.Background(), p)
	second := s.ScanOne(context.Background(), p)
	t.Logf("第一次 cache=%v 命中数=%d; 第二次 cache=%v", first.CacheHit, 0, second.CacheHit)
	if first.CacheHit || !second.CacheHit {
		t.Fatalf("缓存命中行为错误: first=%v second=%v", first.CacheHit, second.CacheHit)
	}
	if first.Status != second.Status || len(first.Matches) != len(second.Matches) {
		t.Fatal("缓存命中改变了结论")
	}
	hits, _ := s.CacheStats()
	if hits < 1 {
		t.Fatalf("期望至少 1 次缓存命中，实际 %d", hits)
	}

	// 文件内容变化 => fileHash 变化 => 缓存失效。
	writeFile(t, dir, "go.mod", goModBad)
	changed := s.ScanOne(context.Background(), p)
	if changed.CacheHit {
		t.Fatal("文件修改后不应命中旧缓存")
	}
	if changed.Status != StatusRejected {
		t.Fatalf("含非法版本的清单状态=%s 期望 rejected", changed.Status)
	}
	for _, is := range changed.Issues {
		t.Logf("缓存失效后重新解析，问题[%s]: %s", is.Code, is.Error())
	}

	// 漏洞库版本变化 => dbRevision 变化 => 缓存失效。
	s2, _ := New(testDB("r2-changed"), Options{Concurrency: 2, UseCache: true})
	revoked := s2.ScanOne(context.Background(), p) // 同一非法文件
	if revoked.CacheHit {
		t.Fatal("漏洞库 revision 变化后不应跨扫描器共享缓存")
	}
	t.Logf("漏洞库版本 r1 -> r2-changed 后重新扫描，DBRevision=%s", revoked.DBRevision)
}

func TestErrorClassificationAndIsolation(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "a/go.mod", goModGood)
	missing := filepath.Join(dir, "nope/go.mod")
	unsupported := writeFile(t, dir, "b/pom.xml", "<project/>")
	broken := writeFile(t, dir, "c/package-lock.json", "{broken json")
	badlist := writeFile(t, dir, "d/package-lock.json",
		`{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"0.1.0"}}}
`)
	_ = badlist

	s, _ := New(testDB("r1"), Options{Concurrency: 3, UseCache: false})
	paths := []string{good, missing, unsupported, broken}
	rep := s.Scan(context.Background(), paths)

	// 结果顺序必须严格等于输入顺序，与并发完成先后无关。
	for i, p := range paths {
		if rep.Results[i].Path != p {
			t.Fatalf("结果顺序漂移: [%d]=%s 期望 %s", i, rep.Results[i].Path, p)
		}
	}
	for _, r := range rep.Results {
		t.Logf("目标 %s => 状态=%s 错误分类=%v", r.Path, r.Status, errKind(r))
	}
	goodRes := rep.Results[0]
	if goodRes.Status != StatusVuln || len(goodRes.Matches) != 1 {
		t.Fatalf("正常目标被其它目标异常污染: status=%s matches=%d", goodRes.Status, len(goodRes.Matches))
	}
	wantKind := map[string]ErrorKind{
		good:        "",
		missing:     KindTargetFailure,
		unsupported: KindTargetFailure,
		broken:      KindParseError,
	}
	for i, p := range paths {
		got := errKind(rep.Results[i])
		if got != wantKind[p] {
			t.Errorf("目标 %s 错误分类=%q 期望 %q", p, got, wantKind[p])
		}
	}
	if rep.Passed() {
		t.Fatal("存在失败目标与漏洞时，整体不得判定为通过")
	}
}

func TestFatalOnNilDB(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("nil 漏洞库应返回致命配置错误")
	} else if se, ok := err.(*ScanError); !ok || se.Kind != KindFatal {
		t.Fatalf("期望 fatal，实际 %v", err)
	}
}

func TestRejectedNotPassedButWarningPassed(t *testing.T) {
	dir := t.TempDir()
	// 仅含警告（环境标记、指令行）的 requirements.txt：成分合法，允许通过。
	onlyWarn := strings.Join([]string{
		"examplepkg==1.0.0",
		"other==1.0.0 ; python_version < \"3.10\"",
		"-r x.txt",
	}, "\n")
	wp := writeFile(t, dir, "requirements.txt", onlyWarn)
	s, _ := New(testDB("r1"), Options{UseCache: false})
	// examplepkg/other 不在 go 漏洞库，且 pypi 库无规则 => 无漏洞。
	wr := s.ScanOne(context.Background(), wp)
	t.Logf("仅警告清单 status=%s issues=%d", wr.Status, len(wr.Issues))
	if wr.Status == StatusRejected {
		t.Fatal("环境标记与指令行属于警告级别，不应判 rejected")
	}

	bad := writeFile(t, dir, "bad/go.mod", goModBad)
	br := s.ScanOne(context.Background(), bad)
	if br.Status != StatusRejected {
		t.Fatalf("含非法版本条目 status=%s 期望 rejected", br.Status)
	}
}

func errKind(r *TargetResult) ErrorKind {
	if r.Err == nil {
		return ""
	}
	return r.Err.Kind
}
