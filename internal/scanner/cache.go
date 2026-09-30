package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// cacheKey 由目标路径、文件内容指纹与漏洞库版本构成；
// 任一变化（文件被修改、漏洞库规则更新）都会导致缓存自动失效。
type cacheKey struct {
	path       string
	fileHash   string
	dbRevision string
}

type resultCache struct {
	mu      sync.Mutex
	entries map[cacheKey]*TargetResult
	// stats 供测试与日志验证命中行为。
	hits   int
	misses int
}

func newResultCache() *resultCache {
	return &resultCache{entries: make(map[cacheKey]*TargetResult)}
}

func (c *resultCache) get(k cacheKey) (*TargetResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.entries[k]
	if ok {
		c.hits++
	} else {
		c.misses++
	}
	if r == nil {
		return nil, ok
	}
	// 返回副本，避免调用方修改污染缓存。
	cp := *r
	return &cp, ok
}

func (c *resultCache) put(k cacheKey, r *TargetResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[k] = r
}

func (c *resultCache) stats() (hits, misses int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:12])
}
