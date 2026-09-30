// Package integration runs end-to-end scenarios through real parsers, the
// local vulnerability database and the concurrent caching engine.
package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/engine"
	_ "github.com/lisama569/sbom-vuln-scanner-go/parse/gomod"
	_ "github.com/lisama569/sbom-vuln-scanner-go/parse/npm"
	"github.com/lisama569/sbom-vuln-scanner-go/scan"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
	"testing/fstest"
)

func loadDB(t *testing.T, rev, body string) *vulndb.Database {
	t.Helper()
	fsys := fstest.MapFS{"db.json": &fstest.MapFile{Data: []byte(body)}}
	db, err := vulndb.LoadFS(fsys, "db.json")
	if err != nil {
		t.Fatalf("db %s: %v", rev, err)
	}
	return db
}

const lockVulnerable = `{
  "name":"app","lockfileVersion":3,
  "packages":{
    "":{"dependencies":{"p":"1.0.0","q":"2.0.0"}},
    "node_modules/p":{"version":"1.0.0"},
    "node_modules/q":{"version":"2.0.0"}
  }
}`

const lockMalformed = `{ "lockfileVersion": 3, "packages": {`

func dbRev(rev string) string {
	return `{"revision":"` + rev + `","advisories":[
	  {"id":"CVE-1","ecosystem":"npm","package":"p",
	   "affected":[[{"op":">=","version":"1.0.0"},{"op":"<","version":"1.5.0"}]]}]}`
}

func writeTarget(t *testing.T, name, content string) scan.Target {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return scan.Target{Format: "npm", Path: p}
}

func TestIntegration_MixedSuccessAndFailure(t *testing.T) {
	db := loadDB(t, "r1", dbRev("r1"))
	good := writeTarget(t, "package-lock.json", lockVulnerable)
	bad := writeTarget(t, "package-lock.json", lockMalformed)

	eng := engine.New(db, 4)
	results := eng.ScanAll(context.Background(), []scan.Target{good, bad, good})

	t.Logf("raw malformed input: %q", lockMalformed)
	t.Logf("raw good input:\n%s", lockVulnerable)

	if len(results) != 3 {
		t.Fatalf("results=%d", len(results))
	}
	if !results[0].OK() {
		t.Fatalf("good target failed: %v", results[0].Failure)
	}
	if results[2] != results[0] {
		t.Fatal("duplicate good target should return the cached result")
	}
	if results[1].OK() {
		t.Fatal("malformed target must not be reported as pass")
	}
	if results[1].Failure.Class != scan.FailureTarget {
		t.Fatalf("malformed class=%s want target_failed", results[1].Failure.Class)
	}
	t.Logf("malformed target failure (distinguishable): %v", results[1].Failure)

	if len(results[0].Findings) != 1 {
		t.Fatalf("findings=%d want 1", len(results[0].Findings))
	}
	f := results[0].Findings[0]
	t.Logf("normalized decision basis: pkg=%s version=%s scope=%s db=%s\n  reason: %s",
		f.Package, f.Version, f.Scope, results[0].DBRevision, f.Reason)
}

func TestIntegration_ReproducibleByRevision(t *testing.T) {
	good := writeTarget(t, "package-lock.json", lockVulnerable)

	// Same revision scanned twice (even after cache invalidation) gives the
	// exact same findings and revision stamp.
	db1 := loadDB(t, "r1", dbRev("r1"))
	eng := engine.New(db1, 4)
	first := eng.ScanAll(context.Background(), []scan.Target{good})[0]
	eng.Invalidate()
	second := eng.ScanAll(context.Background(), []scan.Target{good})[0]
	if first.DBRevision != "r1" || second.DBRevision != "r1" {
		t.Fatalf("revisions %q %q", first.DBRevision, second.DBRevision)
	}
	if len(first.Findings) != len(second.Findings) ||
		first.Findings[0].Reason != second.Findings[0].Reason {
		t.Fatal("same revision + same manifest must reproduce identical conclusion")
	}
	t.Logf("reproduced under %s: %s", second.DBRevision, second.Findings[0].Reason)

	// Rules updated: the fix release is included; only p@1.5.0+ is clean.
	db2Body := `{"revision":"r2","advisories":[
	  {"id":"CVE-1","ecosystem":"npm","package":"p",
	   "affected":[[{"op":">=","version":"1.0.0"},{"op":"<","version":"1.0.0"}]]}]}`
	db2 := loadDB(t, "r2", db2Body)
	eng2 := engine.New(db2, 4)
	updated := eng2.ScanAll(context.Background(), []scan.Target{good})[0]
	if updated.DBRevision != "r2" {
		t.Fatalf("revision=%q want r2", updated.DBRevision)
	}
	if len(updated.Findings) != 0 {
		t.Fatalf("updated rules should yield no findings, got %d", len(updated.Findings))
	}
	t.Logf("rules update r1->r2 changed conclusion (1 finding -> 0); each report carries its revision")
}
