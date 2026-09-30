// Package engine scans multiple targets concurrently with a result cache and
// single-flight coalescing. Concurrency order, cache hits and invalidation
// never change final conclusions.
package engine

import (
	"context"

	"github.com/lisama569/sbom-vuln-scanner-go/scan"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
)

// Engine is a concurrent, caching scanner.
type Engine struct {
	scanner *scan.Scanner
	workers int
	cache   map[string]*scan.Result
	hits    int
	misses  int
}

// New creates an engine for db with the given concurrency (workers <= 1 -> 1).
func New(db *vulndb.Database, workers int) *Engine {
	if workers < 1 {
		workers = 1
	}
	return &Engine{scanner: scan.New(db), workers: workers, cache: map[string]*scan.Result{}}
}

// ScanAll scans all targets concurrently. Duplicate targets are served from
// cache (or coalesced while in flight). One target's failure never affects
// another target's result.
func (e *Engine) ScanAll(ctx context.Context, targets []scan.Target) []*scan.Result { return nil }

// Invalidate clears cached results for the given target keys (all if empty).
func (e *Engine) Invalidate(targets ...scan.Target) {}

// CacheStats reports cache counters for test assertions.
type CacheStats struct {
	Hits   int
	Misses int
}

// Stats returns cumulative cache counters.
func (e *Engine) Stats() CacheStats { return CacheStats{Hits: e.hits, Misses: e.misses} }
