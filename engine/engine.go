// Package engine scans multiple targets concurrently with a result cache and
// single-flight coalescing. Concurrency order, cache hits and invalidation
// never change final conclusions:
//
//   - results are always returned in the input target order;
//   - a repeated target key returns the same *Result pointer (cache hit) or is
//     coalesced with the in-flight scan (single flight), never scanned twice in
//     the same generation;
//   - one target's failure is contained in its own Result and never affects
//     other targets;
//   - Invalidate bumps an engine-wide generation counter. A scan in flight at
//     invalidation time never repopulates the cache, and callers waiting on it
//     observe the new generation and rescan once, so stale conclusions cannot
//     survive invalidation.
package engine

import (
	"context"
	"sync"

	"github.com/lisama569/sbom-vuln-scanner-go/scan"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
)

type cacheEntry struct {
	result     *scan.Result
	generation uint64
}

type flight struct {
	done       chan struct{}
	generation uint64
	result     *scan.Result
}

// Engine is a concurrent, caching scanner.
type Engine struct {
	scanner *scan.Scanner
	workers int

	mu         sync.Mutex
	cache      map[string]cacheEntry
	flights    map[string]*flight
	generation uint64
	hits       int
	misses     int
}

// New creates an engine for db with the given concurrency (workers <= 1 -> 1).
func New(db *vulndb.Database, workers int) *Engine {
	if workers < 1 {
		workers = 1
	}
	return &Engine{
		scanner: scan.New(db),
		workers: workers,
		cache:   map[string]cacheEntry{},
		flights: map[string]*flight{},
	}
}

// ScanAll scans all targets concurrently. The returned slice preserves input
// order, including duplicates (same key => same cached/coalesced result).
func (e *Engine) ScanAll(ctx context.Context, targets []scan.Target) []*scan.Result {
	results := make([]*scan.Result, len(targets))
	sem := make(chan struct{}, e.workers)
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(i int, t scan.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = e.scanOne(ctx, t)
		}(i, t)
	}
	wg.Wait()
	return results
}

// scanOne resolves one key with cache -> in-flight -> fresh-scan precedence.
// It loops because joining an in-flight scan from a stale generation requires
// a retry under the new generation.
func (e *Engine) scanOne(ctx context.Context, t scan.Target) *scan.Result {
	key := t.Key()
	for {
		e.mu.Lock()
		gen := e.generation
		if entry, ok := e.cache[key]; ok && entry.generation == gen {
			e.hits++
			e.mu.Unlock()
			return entry.result
		}
		if f, ok := e.flights[key]; ok && f.generation == gen {
			e.hits++
			e.mu.Unlock()
			<-f.done
			// After waking, verify no invalidation happened while waiting.
			e.mu.Lock()
			if e.generation == gen {
				if entry, ok := e.cache[key]; ok && entry.generation == gen {
					r := entry.result
					e.mu.Unlock()
					return r
				}
				r := f.result // scanner finished but publish path races; f.result is set before close
				e.mu.Unlock()
				return r
			}
			e.mu.Unlock()
			continue // generation advanced -> retry (cache miss / new flight)
		}
		// Start a fresh flight for this generation.
		f := &flight{done: make(chan struct{}), generation: gen}
		e.flights[key] = f
		e.misses++
		e.mu.Unlock()

		r := e.scanner.Scan(ctx, t)

		e.mu.Lock()
		f.result = r
		close(f.done)
		delete(e.flights, key)
		if e.generation == gen {
			e.cache[key] = cacheEntry{result: r, generation: gen}
		}
		e.mu.Unlock()
		return r
	}
}

// Invalidate bumps the generation and drops cached results for the given target
// keys; with no arguments the whole cache is cleared. The next ScanAll rescans
// affected targets; in-flight scans complete but are never cached.
func (e *Engine) Invalidate(targets ...scan.Target) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.generation++
	if len(targets) == 0 {
		e.cache = map[string]cacheEntry{}
		return
	}
	drop := map[string]struct{}{}
	for _, t := range targets {
		drop[t.Key()] = struct{}{}
	}
	for k := range e.cache {
		if _, ok := drop[k]; ok {
			delete(e.cache, k)
		}
	}
}

// CacheStats reports cache counters for test assertions.
type CacheStats struct {
	Hits   int
	Misses int
}

// Stats returns cumulative cache counters.
func (e *Engine) Stats() CacheStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return CacheStats{Hits: e.hits, Misses: e.misses}
}
