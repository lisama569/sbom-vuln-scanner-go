package engine_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/engine"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
	_ "github.com/lisama569/sbom-vuln-scanner-go/parse/npm"
	"github.com/lisama569/sbom-vuln-scanner-go/scan"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
	"testing/fstest"
)

// countParser wraps behavior keyed by path, counting actual Parse invocations
// and recording concurrency overlap. It serves the "count" format on .json
// files and otherwise reports malformed (parse_failed).
type countParser struct {
	calls     int64
	mu        sync.Mutex
	active    int
	maxActive int
	condMu    sync.Mutex
	block     map[string]chan struct{}
}

func (cp *countParser) Format() string { return "count" }

func (cp *countParser) Parse(ctx context.Context, path string) (*component.Manifest, error) {
	atomic.AddInt64(&cp.calls, 1)
	cp.mu.Lock()
	cp.active++
	if cp.active > cp.maxActive {
		cp.maxActive = cp.active
	}
	cp.mu.Unlock()
	defer func() {
		cp.mu.Lock()
		cp.active--
		cp.mu.Unlock()
	}()

	cp.condMu.Lock()
	ch := cp.block[path]
	cp.condMu.Unlock()
	if ch != nil {
		<-ch // emulate a slow target
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &parse.Error{Class: parse.ClassParseFailed, Format: "count", Path: path, Err: err}
	}
	m := parse.Merge("count", path, []component.Component{
		{Ecosystem: "npm", Name: "p", Version: "1.0.0", Scope: component.ScopeDirect,
			Source: component.SourceRef{Format: "count", File: path}},
	}, nil, nil)
	_ = raw
	return m, nil
}

func TestMain(m *testing.M) {
	// ensure npm registration order-independent; nothing extra needed
	os.Exit(m.Run())
}

func newDB(t *testing.T) *vulndb.Database {
	t.Helper()
	content := `{"revision":"r1","advisories":[{"id":"CVE-1","ecosystem":"npm","package":"p",
	  "affected":[[{"op":">=","version":"1.0.0"},{"op":"<","version":"2.0.0"}]]}]}`
	db, err := vulndb.LoadFS(fstest.MapFS{"db.json": &fstest.MapFile{Data: []byte(content)}}, "db.json")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func mkTarget(t *testing.T, tag string) scan.Target {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, tag+".json")
	if err := os.WriteFile(p, []byte(fmt.Sprintf(`{"tag":%q}`, tag)), 0o600); err != nil {
		t.Fatal(err)
	}
	return scan.Target{Format: "count", Path: p}
}

func TestScanAll_OrderAndDedup(t *testing.T) {
	cp := &countParser{block: map[string]chan struct{}{}}
	parse.Register(cp)

	a := mkTarget(t, "a")
	b := mkTarget(t, "b")
	c := mkTarget(t, "c")
	targets := []scan.Target{b, a, b, c, a} // duplicates interleaved
	wantPaths := []string{b.Path, a.Path, b.Path, c.Path, a.Path}

	eng := engine.New(newDB(t), 4)
	got := eng.ScanAll(context.Background(), targets)

	if len(got) != len(targets) {
		t.Fatalf("results=%d want %d", len(got), len(targets))
	}
	for i, r := range got {
		if r.Target.Path != wantPaths[i] {
			t.Errorf("position %d: got %s want %s (order must follow input)", i, r.Target.Path, wantPaths[i])
		}
		if !r.OK() {
			t.Errorf("position %d unexpected failure: %v", i, r.Failure)
		}
	}
	// 3 unique keys => exactly 3 parse calls despite 5 requests.
	if n := atomic.LoadInt64(&cp.calls); n != 3 {
		t.Errorf("parse calls=%d want 3 (single-flight dedup)", n)
	}
	st := eng.Stats()
	if st.Misses != 3 || st.Hits != 2 {
		t.Errorf("stats=%+v want hits=2 misses=3", st)
	}
	// Duplicate positions return the same pointer (identical conclusion).
	if got[1] != got[4] || got[0] != got[2] {
		t.Error("duplicate targets returned different result instances")
	}
}

func TestCache_HitAcrossRunsAndInvalidate(t *testing.T) {
	cp := &countParser{block: map[string]chan struct{}{}}
	parse.Register(cp)
	a := mkTarget(t, "a")
	eng := engine.New(newDB(t), 2)

	eng.ScanAll(context.Background(), []scan.Target{a})
	if n := atomic.LoadInt64(&cp.calls); n != 1 {
		t.Fatalf("calls=%d want 1", n)
	}
	eng.ScanAll(context.Background(), []scan.Target{a})
	if n := atomic.LoadInt64(&cp.calls); n != 1 {
		t.Fatalf("calls=%d want 1 after cache hit (got %d)", n, n)
	}
	eng.Invalidate(a)
	eng.ScanAll(context.Background(), []scan.Target{a})
	if n := atomic.LoadInt64(&cp.calls); n != 2 {
		t.Fatalf("calls=%d want 2 after invalidation", n)
	}
	eng.Invalidate()
	eng.ScanAll(context.Background(), []scan.Target{a})
	if n := atomic.LoadInt64(&cp.calls); n != 3 {
		t.Fatalf("calls=%d want 3 after full invalidation", n)
	}
}

func TestFailure_Isolation(t *testing.T) {
	cp := &countParser{block: map[string]chan struct{}{}}
	parse.Register(cp)
	good := mkTarget(t, "good")
	bad := scan.Target{Format: "count", Path: filepath.Join(t.TempDir(), "missing.json")}
	alsoGood := mkTarget(t, "good2")

	eng := engine.New(newDB(t), 3)
	got := eng.ScanAll(context.Background(), []scan.Target{good, bad, alsoGood})
	if len(got) != 3 {
		t.Fatalf("results=%d", len(got))
	}
	if !got[0].OK() {
		t.Errorf("good target poisoned: %v", got[0].Failure)
	}
	if got[1].OK() || got[1].Failure.Class != scan.FailureTarget {
		t.Errorf("bad target should be target_failed: %+v", got[1])
	}
	if !got[2].OK() {
		t.Errorf("other good target poisoned: %v", got[2].Failure)
	}
	t.Logf("isolated failure: %s", got[1].Failure)
}

func TestConcurrent_RepeatedSameTargetSingleFlight(t *testing.T) {
	cp := &countParser{block: map[string]chan struct{}{}}
	parse.Register(cp)
	a := mkTarget(t, "slow")
	release := make(chan struct{})
	cp.block[a.Path] = release

	eng := engine.New(newDB(t), 8)
	var wg sync.WaitGroup
	results := make([]*scan.Result, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = eng.ScanAll(context.Background(), []scan.Target{a})[0]
		}(i)
	}
	// Give goroutines time to pile up on the flight, then release.
	close(release)
	wg.Wait()

	if n := atomic.LoadInt64(&cp.calls); n != 1 {
		t.Errorf("parse calls=%d want 1 under concurrent single-flight", n)
	}
	first := results[0]
	for i, r := range results {
		if r != first {
			t.Errorf("result %d differs from cached pointer", i)
		}
	}
}
