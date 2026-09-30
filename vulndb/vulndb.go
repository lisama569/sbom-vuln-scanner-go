// Package vulndb loads a local, file-based vulnerability database.
//
// The database is content-addressed by Revision (e.g. a hash of the loaded
// rules): scan reports embed the revision so that historical conclusions can
// be reproduced against the same database snapshot even after the rules file
// is updated.
package vulndb

import (
	"fmt"
	"io/fs"
)

// Advisory describes one vulnerability affecting one package.
type Advisory struct {
	ID        string // e.g. CVE-2024-0001
	Ecosystem string
	Package   string
	// Affected is a union of affected version intervals.
	Affected []Range
	// Summary is short human-readable text.
	Summary string
}

// Range is one intersection of bounds (AND group).
// Bounds should normally contain one lower and one upper bound.
type Range struct {
	Bounds []Bound
}

// Bound mirrors semver.Bound to keep the on-disk DB model self-contained.
type Bound struct {
	Op  string // "=", "!=", ">", ">=", "<", "<="
	Ver string // raw version, parsed at load time
}

// Database is a loaded, immutable vulnerability database snapshot.
type Database struct {
	// Revision identifies the exact content of this snapshot.
	Revision   string
	advisories []Advisory
}

// Advisories returns all advisories in the snapshot.
func (d *Database) Advisories() []Advisory { return d.advisories }

// ForPackage returns advisories for one ecosystem/package pair.
func (d *Database) ForPackage(ecosystem, pkg string) []Advisory { return nil }

// LoadFile loads a database from a JSON file on the local filesystem.
func LoadFile(path string) (*Database, error) {
	return nil, fmt.Errorf("vulndb: not implemented")
}

// LoadFS loads a database from the given filesystem rooted at dir.
func LoadFS(fsys fs.FS, path string) (*Database, error) {
	return nil, fmt.Errorf("vulndb: not implemented")
}
