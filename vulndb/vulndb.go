// Package vulndb loads a local, file-based vulnerability database.
//
// On-disk JSON format:
//
//	{
//	  "revision": "2024-09-01",
//	  "advisories": [
//	    {
//	      "id": "CVE-2024-0001",
//	      "ecosystem": "npm",
//	      "package": "left-pad",
//	      "summary": "...",
//	      "affected": [
//	        [ { "op": ">=", "version": "1.0.0" }, { "op": "<", "version": "1.5.0" } ]
//	      ]
//	    }
//	  ]
//	}
//
// "affected" is a list of AND groups (each a list of bounds); groups are
// OR-ed. A "fixed in 1.5.0" advisory is expressed as "< 1.5.0" plus a lower
// bound. Every bound version and every advisory record is validated at load
// time: a malformed database is rejected outright, never partially applied.
//
// Revision identifies the exact snapshot scan reports embed, so a manifest's
// historical conclusion can be reproduced even after the rules file changes.
package vulndb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"

	"github.com/lisama569/sbom-vuln-scanner-go/semver"
)

// Range is one AND group of bounds.
type Range struct {
	Bounds []Bound
}

// Bound is one comparison boundary of an affected range.
type Bound struct {
	Op  string `json:"op"`
	Ver string `json:"version"`
}

// Advisory describes one vulnerability affecting one package.
type Advisory struct {
	ID        string  `json:"id"`
	Ecosystem string  `json:"ecosystem"`
	Package   string  `json:"package"`
	Summary   string  `json:"summary"`
	Affected  []Range `json:"affected"`
}

// rawAdvisory/RawRange use []Bound arrays per the on-disk format.
type rawAdvisory struct {
	ID        string    `json:"id"`
	Ecosystem string    `json:"ecosystem"`
	Package   string    `json:"package"`
	Summary   string    `json:"summary"`
	Affected  [][]Bound `json:"affected"`
}

type rawDB struct {
	Revision   string        `json:"revision"`
	Advisories []rawAdvisory `json:"advisories"`
}

// Database is a loaded, immutable vulnerability database snapshot.
type Database struct {
	// Revision identifies the exact content of this snapshot. When the source
	// file supplies one it is used verbatim; otherwise a sha256 content hash
	// prefix is assigned.
	Revision   string
	advisories []Advisory
	byPackage  map[string][]Advisory
}

// Advisories returns all advisories in the snapshot, sorted by ID.
func (d *Database) Advisories() []Advisory {
	out := make([]Advisory, len(d.advisories))
	copy(out, d.advisories)
	return out
}

// ForPackage returns advisories for one ecosystem/package pair, sorted by ID.
func (d *Database) ForPackage(ecosystem, pkg string) []Advisory {
	return d.byPackage[ecosystem+":"+pkg]
}

// LoadFile loads a database from a JSON file on the local filesystem.
func LoadFile(path string) (*Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("vulndb: open %s: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("vulndb: read %s: %w", path, err)
	}
	return parseDB(raw)
}

// LoadFS loads a database from the given filesystem at path.
func LoadFS(fsys fs.FS, path string) (*Database, error) {
	raw, err := fs.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("vulndb: read %s: %w", path, err)
	}
	return parseDB(raw)
}

func parseDB(raw []byte) (*Database, error) {
	var rd rawDB
	if err := json.Unmarshal(raw, &rd); err != nil {
		return nil, fmt.Errorf("vulndb: invalid JSON: %w", err)
	}

	db := &Database{Revision: rd.Revision, byPackage: map[string][]Advisory{}}
	seenID := map[string]struct{}{}
	for i, ra := range rd.Advisories {
		if ra.ID == "" {
			return nil, fmt.Errorf("vulndb: advisory #%d: missing id", i+1)
		}
		if _, dup := seenID[ra.ID]; dup {
			return nil, fmt.Errorf("vulndb: advisory #%d: duplicate id %q", i+1, ra.ID)
		}
		seenID[ra.ID] = struct{}{}
		if ra.Ecosystem == "" {
			return nil, fmt.Errorf("vulndb: advisory %s: missing ecosystem", ra.ID)
		}
		if ra.Package == "" {
			return nil, fmt.Errorf("vulndb: advisory %s: missing package", ra.ID)
		}
		if len(ra.Affected) == 0 {
			return nil, fmt.Errorf("vulndb: advisory %s: affected must not be empty", ra.ID)
		}
		a := Advisory{ID: ra.ID, Ecosystem: ra.Ecosystem, Package: ra.Package, Summary: ra.Summary}
		for gi, group := range ra.Affected {
			if len(group) == 0 {
				return nil, fmt.Errorf("vulndb: advisory %s: affected group #%d is empty", ra.ID, gi+1)
			}
			r := Range{}
			for _, b := range group {
				switch b.Op {
				case string(semver.OpEq), string(semver.OpNe), string(semver.OpGt),
					string(semver.OpGte), string(semver.OpLt), string(semver.OpLte):
				default:
					return nil, fmt.Errorf("vulndb: advisory %s: unknown op %q", ra.ID, b.Op)
				}
				if _, err := semver.Parse(b.Ver); err != nil {
					return nil, fmt.Errorf("vulndb: advisory %s: invalid bound version %q: %w", ra.ID, b.Ver, err)
				}
				r.Bounds = append(r.Bounds, b)
			}
			a.Affected = append(a.Affected, r)
		}
		db.advisories = append(db.advisories, a)
	}
	// Deterministic ordering regardless of file order: by ID.
	sort.Slice(db.advisories, func(i, j int) bool { return db.advisories[i].ID < db.advisories[j].ID })
	for _, a := range db.advisories {
		k := a.Ecosystem + ":" + a.Package
		db.byPackage[k] = append(db.byPackage[k], a)
	}
	if db.Revision == "" {
		sum := sha256.Sum256(raw)
		db.Revision = "sha256:" + hex.EncodeToString(sum[:])[:16]
	}
	return db, nil
}
