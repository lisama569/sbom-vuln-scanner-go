package scan_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
	_ "github.com/lisama569/sbom-vuln-scanner-go/parse/npm"
	"github.com/lisama569/sbom-vuln-scanner-go/scan"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
	"testing/fstest"
)

// brokenParser always returns a ClassInternal error, to prove the scanner
// distinguishes "parser blew up" from "bad input".
type brokenParser struct{}

func (brokenParser) Format() string { return "broken" }
func (brokenParser) Parse(ctx context.Context, path string) (*component.Manifest, error) {
	return nil, &parse.Error{Class: parse.ClassInternal, Format: "broken", Path: path, Err: errors.New("boom")}
}

func init() { parse.Register(brokenParser{}) }

const dbJSON = `{
 "revision":"r1",
 "advisories":[{"id":"CVE-1","ecosystem":"npm","package":"p",
   "affected":[[{"op":">=","version":"1.0.0"},{"op":"<","version":"2.0.0"}]]}]}`

func newDB(t *testing.T) *vulndb.Database {
	t.Helper()
	db, err := vulndb.LoadFS(fstest.MapFS{"db.json": &fstest.MapFile{Data: []byte(dbJSON)}}, "db.json")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScan_Success(t *testing.T) {
	lock := writeFile(t, "package-lock.json", `{
	  "lockfileVersion":3,
	  "packages":{"":{"dependencies":{"p":"1.0.0"}},"node_modules/p":{"version":"1.0.0"}}}`)
	r := scan.New(newDB(t)).Scan(context.Background(), scan.Target{Format: "npm", Path: lock})
	if !r.OK() {
		t.Fatalf("expected ok, got failure %v", r.Failure)
	}
	if len(r.Findings) != 1 || r.Findings[0].AdvisoryID != "CVE-1" {
		t.Fatalf("findings=%+v", r.Findings)
	}
	t.Logf("finding: %s", r.Findings[0].Reason)
}

func TestScan_TargetFailures(t *testing.T) {
	s := scan.New(newDB(t))

	// Unknown format.
	r := s.Scan(context.Background(), scan.Target{Format: "nope", Path: "x"})
	if r.OK() || r.Failure.Class != scan.FailureTarget {
		t.Fatalf("unknown format: %+v", r)
	}
	t.Logf("unknown-format -> %s", r.Failure)

	// Malformed file.
	bad := writeFile(t, "package-lock.json", `{ broken`)
	r = s.Scan(context.Background(), scan.Target{Format: "npm", Path: bad})
	if r.OK() || r.Failure.Class != scan.FailureTarget {
		t.Fatalf("malformed file: %+v", r)
	}
	t.Logf("malformed -> %s", r.Failure)

	// Missing file.
	r = s.Scan(context.Background(), scan.Target{Format: "npm", Path: filepath.Join(t.TempDir(), "z")})
	if r.OK() || r.Failure.Class != scan.FailureTarget {
		t.Fatalf("missing file: %+v", r)
	}
}

func TestScan_InternalFailure(t *testing.T) {
	r := scan.New(newDB(t)).Scan(context.Background(), scan.Target{Format: "broken", Path: "x"})
	if r.OK() {
		t.Fatal("broken parser should not be OK")
	}
	if r.Failure.Class != scan.FailureInternal {
		t.Fatalf("class=%s want internal", r.Failure.Class)
	}
	t.Logf("internal -> %s", r.Failure)
}

func TestScan_NilDB_Internal(t *testing.T) {
	r := scan.New(nil).Scan(context.Background(), scan.Target{Format: "npm", Path: "x"})
	if r.OK() || r.Failure.Class != scan.FailureInternal {
		t.Fatalf("nil db: %+v", r)
	}
}
