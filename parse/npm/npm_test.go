package npm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
)

func writeLock(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func logManifest(t *testing.T, raw string, m *component.Manifest) {
	t.Helper()
	t.Logf("raw input:\n%s", raw)
	for _, c := range m.Components {
		t.Logf("normalized: id=%s scope=%s deps=%v", c.ID(), c.Scope, c.DependsOn)
	}
	for _, r := range m.Rejected {
		t.Logf("rejected: reason=%s detail=%s raw=%s", r.Reason, r.Detail, r.Raw)
	}
	for _, w := range m.Warnings {
		t.Logf("warning: code=%s detail=%s", w.Code, w.Detail)
	}
}

func TestParseV3_DirectTransitiveDedup(t *testing.T) {
	raw := `{
	  "name": "app",
	  "lockfileVersion": 3,
	  "packages": {
	    "": {
	      "dependencies": { "left-pad": "^1.2.0", "lodash": "^4.0.0" }
	    },
	    "node_modules/left-pad": { "version": "1.2.0" },
	    "node_modules/lodash": { "version": "4.17.21" },
	    "node_modules/lodash/node_modules/left-pad": { "version": "1.2.0" }
	  }
	}`
	p := writeLock(t, raw)
	m, err := New().Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	logManifest(t, raw, m)

	scopeByName := map[string]component.Scope{}
	for _, c := range m.Components {
		scopeByName[c.Name] = c.Scope
	}
	if scopeByName["left-pad"] != component.ScopeDirect {
		t.Errorf("left-pad scope=%s want direct (direct wins)", scopeByName["left-pad"])
	}
	if scopeByName["lodash"] != component.ScopeDirect {
		t.Errorf("lodash scope=%s", scopeByName["lodash"])
	}
	if len(m.Components) != 2 {
		t.Errorf("components=%d want 2 after dedup", len(m.Components))
	}
}

func TestParseV1_Tree(t *testing.T) {
	raw := `{
	  "name": "app",
	  "lockfileVersion": 1,
	  "dependencies": {
	    "a": { "version": "1.0.0", "requires": {"b":"2.0.0"},
	      "dependencies": { "b": { "version": "2.0.0" } } },
	    "c": { "version": "0.1.0" }
	  }
	}`
	p := writeLock(t, raw)
	m, err := New().Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	logManifest(t, raw, m)
	if len(m.Components) != 3 {
		t.Fatalf("components=%d want 3", len(m.Components))
	}
	sc := map[string]component.Scope{}
	for _, c := range m.Components {
		sc[c.Name] = c.Scope
	}
	if sc["a"] != component.ScopeDirect || sc["c"] != component.ScopeDirect {
		t.Errorf("v1 top-level should be direct: %+v", sc)
	}
	if sc["b"] != component.ScopeTransitive {
		t.Errorf("nested b should be transitive: %+v", sc)
	}
}

func TestParse_MalformedJSON_ClassParseFailed(t *testing.T) {
	raw := `{ "lockfileVersion": 3, "packages": {`
	p := writeLock(t, raw)
	_, err := New().Parse(context.Background(), p)
	var pe *parse.Error
	if !errors.As(err, &pe) {
		t.Fatalf("want *parse.Error, got %v", err)
	}
	if pe.Class != parse.ClassParseFailed {
		t.Fatalf("class=%s want parse_failed", pe.Class)
	}
	t.Logf("raw=%q -> %v", raw, err)
}

func TestParse_MissingFile_ClassParseFailed(t *testing.T) {
	_, err := New().Parse(context.Background(), filepath.Join(t.TempDir(), "nope.json"))
	var pe *parse.Error
	if !errors.As(err, &pe) || pe.Class != parse.ClassParseFailed {
		t.Fatalf("got %v", err)
	}
}

func TestParse_RejectedRecordsDistinguishable(t *testing.T) {
	raw := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "dependencies": { "ok": "1.0.0", "badver": "1.0.0", "nover": "1.0.0", "linkpkg": "1.0.0" } },
	    "node_modules/ok": { "version": "1.0.0" },
	    "node_modules/badver": { "version": "not-semver" },
	    "node_modules/nover": { "version": "" },
	    "node_modules/linkpkg": { "version": "9.9.9", "link": true },
	    "node_modules/@scope/pkg": { "version": "2.0.0" }
	  }
	}`
	p := writeLock(t, raw)
	m, err := New().Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	logManifest(t, raw, m)

	reasons := map[component.RejectReason]bool{}
	for _, r := range m.Rejected {
		reasons[r.Reason] = true
	}
	if !reasons[component.RejectInvalidVersion] {
		t.Errorf("want invalid_version rejection")
	}
	if !reasons[component.RejectMissingVersion] {
		t.Errorf("want missing_version rejection")
	}
	names := map[string]bool{}
	for _, c := range m.Components {
		names[c.Name] = true
	}
	if !names["ok"] || !names["@scope/pkg"] {
		t.Errorf("accepted set wrong: %v", names)
	}
	if names["badver"] || names["nover"] || names["linkpkg"] {
		t.Errorf("rejected/link entries leaked into components: %v", names)
	}
	var sawLink bool
	for _, w := range m.Warnings {
		if w.Code == "link_skipped" {
			sawLink = true
		}
	}
	if !sawLink {
		t.Error("link_skipped warning missing")
	}
}

func TestParse_EmptyLockfile_ParseFailed(t *testing.T) {
	raw := `{"name": "app", "lockfileVersion": 3}`
	p := writeLock(t, raw)
	_, err := New().Parse(context.Background(), p)
	var pe *parse.Error
	if !errors.As(err, &pe) || pe.Class != parse.ClassParseFailed {
		t.Fatalf("got %v", err)
	}
	t.Logf("raw=%q -> %v", raw, err)
}

func TestParseV3_NestedScopedTransitive(t *testing.T) {
	raw := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "dependencies": { "top": "1.0.0" } },
	    "node_modules/top": { "version": "1.0.0" },
	    "node_modules/top/node_modules/@scope/nested": { "version": "2.0.0" },
	    "node_modules/@scope/direct": { "version": "3.0.0" }
	  }
	}`
	p := writeLock(t, raw)
	m, err := New().Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	logManifest(t, raw, m)
	sc := map[string]component.Scope{}
	for _, c := range m.Components {
		sc[c.Name] = c.Scope
	}
	if sc["top"] != component.ScopeDirect {
		t.Errorf("top scope=%s", sc["top"])
	}
	if sc["@scope/nested"] != component.ScopeTransitive {
		t.Errorf("nested scoped scope=%s want transitive", sc["@scope/nested"])
	}
	if sc["@scope/direct"] != component.ScopeTransitive {
		t.Errorf("undecclared top-level scoped is transitive by convention, got %s", sc["@scope/direct"])
	}
}
