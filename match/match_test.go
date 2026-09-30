package match

import (
	"testing"

	"github.com/lisama569/sbom-vuln-scanner-go/component"
	"github.com/lisama569/sbom-vuln-scanner-go/parse"
	"github.com/lisama569/sbom-vuln-scanner-go/vulndb"
	"testing/fstest"
)

func loadDB(t *testing.T, content string) *vulndb.Database {
	t.Helper()
	fsys := fstest.MapFS{"db.json": &fstest.MapFile{Data: []byte(content)}}
	db, err := vulndb.LoadFS(fsys, "db.json")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// boundaryDB: affected >=1.0.0 <1.5.0 (fixed in 1.5.0), union with 2.x.
const boundaryDB = `{
 "revision":"r1",
 "advisories":[
   {"id":"CVE-RANGE","ecosystem":"npm","package":"p","summary":"range+union",
    "affected":[
      [{"op":">=","version":"1.0.0"},{"op":"<","version":"1.5.0"}],
      [{"op":">=","version":"2.0.0"},{"op":"<","version":"2.1.0"}]
    ]},
   {"id":"CVE-EXACT","ecosystem":"npm","package":"q","summary":"exact pin",
    "affected":[[{"op":"=","version":"3.0.0"}]]}
 ]
}`

func TestMatch_Boundaries(t *testing.T) {
	db := loadDB(t, boundaryDB)
	vers := []string{"1.0.0", "1.4.9", "1.5.0", "1.5.0-alpha", "2.0.0", "2.1.0", "2.1.0-rc.1", "3.0.0", "3.0.1"}
	for _, ver := range vers {
		m := parse.Merge("npm", "f", []component.Component{
			{Ecosystem: "npm", Name: "p", Version: ver, Scope: component.ScopeDirect},
			{Ecosystem: "npm", Name: "q", Version: ver, Scope: component.ScopeDirect},
		}, nil, nil)
		found, err := New(db).Match(m)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, f := range found {
			ids[f.AdvisoryID] = true
			t.Logf("ver=%-12s -> %s | %s", ver, f.AdvisoryID, f.Reason)
		}
		wantP := map[string]bool{
			"1.0.0": true, "1.4.9": true, "1.5.0-alpha": true,
			"2.0.0": true, "2.1.0-rc.1": true,
		}
		if ids["CVE-RANGE"] != wantP[ver] {
			t.Errorf("p@%s CVE-RANGE=%v want %v", ver, ids["CVE-RANGE"], wantP[ver])
		}
		if ids["CVE-EXACT"] != (ver == "3.0.0") {
			t.Errorf("q@%s CVE-EXACT=%v", ver, ids["CVE-EXACT"])
		}
	}
}

func TestMatch_DirectTransitiveCountedOnce(t *testing.T) {
	db := loadDB(t, boundaryDB)
	// Same ID twice (direct+transitive) -> merge -> exactly one finding.
	m := parse.Merge("npm", "f", []component.Component{
		{Ecosystem: "npm", Name: "p", Version: "1.2.0", Scope: component.ScopeTransitive},
		{Ecosystem: "npm", Name: "p", Version: "1.2.0", Scope: component.ScopeDirect},
	}, nil, nil)
	found, err := New(db).Match(m)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(found); n != 1 {
		t.Fatalf("findings=%d want 1: %+v", n, found)
	}
	if found[0].Scope != component.ScopeDirect {
		t.Errorf("scope=%s want direct", found[0].Scope)
	}
	t.Logf("dedup finding: %s", found[0].Reason)
}

func TestMatch_MultipleVersionsNoMissNoDoubleCount(t *testing.T) {
	db := loadDB(t, boundaryDB)
	m := parse.Merge("npm", "f", []component.Component{
		{Ecosystem: "npm", Name: "p", Version: "1.2.0", Scope: component.ScopeDirect},     // vulnerable
		{Ecosystem: "npm", Name: "p", Version: "1.5.0", Scope: component.ScopeTransitive}, // fixed
	}, nil, nil)
	found, err := New(db).Match(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("findings=%d want exactly 1 (1.2.0 hit, 1.5.0 clean)", len(found))
	}
	if found[0].Version != "1.2.0" {
		t.Errorf("hit version=%s", found[0].Version)
	}
	// Deterministic order on repeated runs.
	second, _ := New(db).Match(m)
	if len(second) != 1 || second[0].Reason != found[0].Reason {
		t.Errorf("repeat run not reproducible")
	}
}

func TestMatch_SortedOutput(t *testing.T) {
	db := loadDB(t, boundaryDB)
	m := parse.Merge("npm", "f", []component.Component{
		{Ecosystem: "npm", Name: "q", Version: "3.0.0"},
		{Ecosystem: "npm", Name: "p", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "p", Version: "1.0.0"},
	}, nil, nil)
	found, err := New(db).Match(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 {
		t.Fatalf("findings=%d want 3", len(found))
	}
	if found[0].Package != "p" || found[0].Version != "1.0.0" || found[1].Version != "2.0.0" || found[2].Package != "q" {
		t.Errorf("order wrong: %+v", found)
	}
}
