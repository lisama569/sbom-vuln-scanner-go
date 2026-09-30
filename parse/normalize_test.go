package parse

import (
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
)

func TestMerge_DirectWinsAndDedup(t *testing.T) {
	src := component.SourceRef{Format: "npm", File: "f", RawKey: "node_modules/x"}
	comps := []component.Component{
		{Ecosystem: "npm", Name: "x", Version: "1.0.0", Scope: component.ScopeTransitive, Source: src},
		{Ecosystem: "npm", Name: "x", Version: "1.0.0", Scope: component.ScopeDirect, Source: src},
	}
	m := Merge("npm", "f", comps, nil, nil)
	if len(m.Components) != 1 {
		t.Fatalf("components=%d want 1", len(m.Components))
	}
	if m.Components[0].Scope != component.ScopeDirect {
		t.Errorf("scope=%s want direct", m.Components[0].Scope)
	}
	found := false
	for _, w := range m.Warnings {
		t.Logf("warning: %s %s", w.Code, w.Detail)
		if w.Code == "scope_dedup" {
			found = true
		}
	}
	if !found {
		t.Errorf("scope_dedup warning missing")
	}
}

func TestMerge_MultipleVersionsKept(t *testing.T) {
	src := component.SourceRef{Format: "npm", File: "f"}
	comps := []component.Component{
		{Ecosystem: "npm", Name: "x", Version: "2.0.0", Scope: component.ScopeTransitive, Source: src},
		{Ecosystem: "npm", Name: "x", Version: "1.0.0", Scope: component.ScopeDirect, Source: src},
	}
	m := Merge("npm", "f", comps, nil, nil)
	if len(m.Components) != 2 {
		t.Fatalf("components=%d want 2", len(m.Components))
	}
	if m.Components[0].Version != "1.0.0" || m.Components[1].Version != "2.0.0" {
		t.Errorf("not sorted: %s %s", m.Components[0].Version, m.Components[1].Version)
	}
	cnt := 0
	for _, w := range m.Warnings {
		if w.Code == "multiple_versions" {
			cnt++
			t.Logf("warning: %s", w.Detail)
		}
	}
	if cnt != 2 {
		t.Errorf("multiple_versions warnings=%d want 2", cnt)
	}
}

func TestMerge_RejectedSorted(t *testing.T) {
	rej := []component.Rejected{
		{Reason: component.RejectMissingName, Source: component.SourceRef{File: "f", Line: 5}},
		{Reason: component.RejectInvalidVersion, Source: component.SourceRef{File: "f", Line: 2}},
	}
	m := Merge("npm", "f", nil, rej, nil)
	if m.Rejected[0].Source.Line != 2 || m.Rejected[1].Source.Line != 5 {
		t.Errorf("rejected not sorted: %+v", m.Rejected)
	}
}
