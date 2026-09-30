package gomod

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
)

func writeMod(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func logMod(t *testing.T, raw string, m *component.Manifest) {
	t.Helper()
	t.Logf("raw go.mod:\n%s", raw)
	for _, c := range m.Components {
		t.Logf("normalized: id=%s scope=%s line=%d", c.ID(), c.Scope, c.Source.Line)
	}
	for _, r := range m.Rejected {
		t.Logf("rejected: line=%d reason=%s detail=%s raw=%q", r.Source.Line, r.Reason, r.Detail, r.Raw)
	}
	for _, w := range m.Warnings {
		t.Logf("warning: line=%d code=%s detail=%s", w.Source.Line, w.Code, w.Detail)
	}
}

func TestParse_OK(t *testing.T) {
	raw := `module example.com/app

go 1.21

require (
	github.com/a/b v1.2.3 // indirect
	github.com/c/d/v2 v2.0.0
)

require github.com/e/f v0.1.0
`
	p := writeMod(t, raw)
	m, err := New().Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	logMod(t, raw, m)
	if len(m.Rejected) != 0 {
		t.Fatalf("unexpected rejects: %+v", m.Rejected)
	}
	want := map[string]string{
		"github.com/a/b":    "1.2.3",
		"github.com/c/d/v2": "2.0.0",
		"github.com/e/f":    "0.1.0",
	}
	got := map[string]string{}
	for _, c := range m.Components {
		got[c.Name] = c.Version
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s=%q want %q", k, got[k], v)
		}
	}
}

func TestParse_RejectedReasons(t *testing.T) {
	raw := `module x
require github.com/good/x v1.0.0
require github.com/bad/v v01.0.0
require bad~path v1.0.0
require github.com/short
`
	p := writeMod(t, raw)
	m, err := New().Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	logMod(t, raw, m)
	reasons := map[component.RejectReason]int{}
	for _, r := range m.Rejected {
		reasons[r.Reason]++
	}
	if reasons[component.RejectInvalidVersion] != 1 {
		t.Errorf("invalid_version count=%d", reasons[component.RejectInvalidVersion])
	}
	if reasons[component.RejectMissingName] != 1 {
		t.Errorf("missing_name(bad path) count=%d", reasons[component.RejectMissingName])
	}
	if reasons[component.RejectMalformedEntry] != 1 {
		t.Errorf("malformed_entry count=%d", reasons[component.RejectMalformedEntry])
	}
	if len(m.Components) != 1 || m.Components[0].Name != "github.com/good/x" {
		t.Errorf("accepted components wrong: %+v", m.Components)
	}
}

func TestParse_ReplaceApplied(t *testing.T) {
	raw := `module x
require github.com/a/b v1.0.0
replace github.com/a/b => github.com/a/b v1.0.1
`
	p := writeMod(t, raw)
	m, err := New().Parse(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	logMod(t, raw, m)
	if m.Components[0].Version != "1.0.1" {
		t.Errorf("effective version=%s want 1.0.1", m.Components[0].Version)
	}
	var saw bool
	for _, w := range m.Warnings {
		if w.Code == "replace_version" {
			saw = true
		}
	}
	if !saw {
		t.Error("replace_version warning missing")
	}
}

func TestParse_UnterminatedBlock(t *testing.T) {
	raw := "module x\nrequire (\n\tgithub.com/a/b v1.0.0\n"
	p := writeMod(t, raw)
	_, err := New().Parse(context.Background(), p)
	var pe *parse.Error
	if !errors.As(err, &pe) || pe.Class != parse.ClassParseFailed {
		t.Fatalf("got %v", err)
	}
	t.Logf("raw=%q -> %v", raw, err)
}

func TestParse_MissingFile(t *testing.T) {
	_, err := New().Parse(context.Background(), filepath.Join(t.TempDir(), "go.mod"))
	var pe *parse.Error
	if !errors.As(err, &pe) || pe.Class != parse.ClassParseFailed {
		t.Fatalf("got %v", err)
	}
}
