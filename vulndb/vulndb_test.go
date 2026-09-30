package vulndb

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadFS_OK(t *testing.T) {
	content := `{
	  "revision": "2024-09-01",
	  "advisories": [
	    {"id":"CVE-B","ecosystem":"npm","package":"y","summary":"s2","affected":[[{"op":">=","version":"2.0.0"},{"op":"<","version":"3.0.0"}]]},
	    {"id":"CVE-A","ecosystem":"npm","package":"x","summary":"s1","affected":[[{"op":">=","version":"1.0.0"},{"op":"<","version":"1.5.0"}]]}
	  ]
	}`
	fsys := fstest.MapFS{"db.json": &fstest.MapFile{Data: []byte(content)}}
	db, err := LoadFS(fsys, "db.json")
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if db.Revision != "2024-09-01" {
		t.Errorf("revision=%q", db.Revision)
	}
	if got := db.Advisories(); len(got) != 2 || got[0].ID != "CVE-A" {
		t.Fatalf("advisories not sorted/stable: %+v", got)
	}
	if a := db.ForPackage("npm", "x"); len(a) != 1 || a[0].ID != "CVE-A" {
		t.Fatalf("ForPackage npm/x = %+v", a)
	}
	if a := db.ForPackage("npm", "missing"); len(a) != 0 {
		t.Fatalf("unexpected: %+v", a)
	}
}

func TestLoadFS_InvalidRejected(t *testing.T) {
	bads := map[string]string{
		"bad json":          `{not json`,
		"missing id":        `{"advisories":[{"ecosystem":"npm","package":"x","affected":[[{"op":">=","version":"1.0.0"}]]}]}`,
		"duplicate id":      `{"advisories":[{"id":"CVE-1","ecosystem":"npm","package":"x","affected":[[{"op":">=","version":"1.0.0"}]]},{"id":"CVE-1","ecosystem":"npm","package":"y","affected":[[{"op":">=","version":"1.0.0"}]]}]}`,
		"missing ecosystem": `{"advisories":[{"id":"CVE-1","package":"x","affected":[[{"op":">=","version":"1.0.0"}]]}]}`,
		"missing package":   `{"advisories":[{"id":"CVE-1","ecosystem":"npm","affected":[[{"op":">=","version":"1.0.0"}]]}]}`,
		"empty affected":    `{"advisories":[{"id":"CVE-1","ecosystem":"npm","package":"x","affected":[]}]}`,
		"empty group":       `{"advisories":[{"id":"CVE-1","ecosystem":"npm","package":"x","affected":[[]]}]}`,
		"unknown op":        `{"advisories":[{"id":"CVE-1","ecosystem":"npm","package":"x","affected":[[{"op":"~","version":"1.0.0"}]]}]}`,
		"invalid bound ver": `{"advisories":[{"id":"CVE-1","ecosystem":"npm","package":"x","affected":[[{"op":">=","version":"01.0.0"}]]}]}`,
	}
	for name, content := range bads {
		fsys := fstest.MapFS{"db.json": &fstest.MapFile{Data: []byte(content)}}
		_, err := LoadFS(fsys, "db.json")
		if err == nil {
			t.Errorf("%s: expected error", name)
			continue
		}
		t.Logf("case %-18s raw=%q -> reject: %v", name, content, err)
	}
}

func TestLoadFS_AutoRevision(t *testing.T) {
	content := `{"advisories":[{"id":"CVE-1","ecosystem":"npm","package":"x","affected":[[{"op":"=","version":"1.0.0"}]]}]}`
	fsys := fstest.MapFS{"db.json": &fstest.MapFile{Data: []byte(content)}}
	db, err := LoadFS(fsys, "db.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(db.Revision, "sha256:") {
		t.Errorf("auto revision = %q", db.Revision)
	}
}
