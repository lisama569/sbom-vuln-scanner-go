// Package component defines the unified component model that all manifest
// parsers normalize into.
package component

// Scope describes how a component is included in a target.
type Scope int

const (
	ScopeUnknown Scope = iota
	ScopeDirect
	ScopeTransitive
)

func (s Scope) String() string {
	switch s {
	case ScopeDirect:
		return "direct"
	case ScopeTransitive:
		return "transitive"
	default:
		return "unknown"
	}
}

// Component is one normalized dependency entry.
type Component struct {
	Ecosystem string // e.g. "npm", "gomod"
	Name      string
	Version   string // raw version string as found in the manifest
	Scope     Scope
	// DependsOn lists component IDs ("ecosystem:name@version") this one requires.
	DependsOn []string
	// Source records file/format provenance for reproducibility.
	Source SourceRef
}

// SourceRef records where a component (or rejected record) came from.
type SourceRef struct {
	Format string
	File   string
	Line   int // 0 when the format has no stable line number
	RawKey string
}

// ID returns the stable identifier of a component instance.
func (c Component) ID() string { return c.Ecosystem + ":" + c.Name + "@" + c.Version }

// Key returns the identity key used for direct/transitive dedup.
// Same ecosystem+name (regardless of version) collapse into one Key; version
// conflicts are reported separately as RejectVersionConflict.
func (c Component) Key() string { return c.Ecosystem + ":" + c.Name }

// RejectReason categorizes why a raw record was refused.
type RejectReason string

const (
	RejectMalformedEntry    RejectReason = "malformed_entry"
	RejectMissingName       RejectReason = "missing_name"
	RejectMissingVersion    RejectReason = "missing_version"
	RejectInvalidVersion    RejectReason = "invalid_version"
	RejectVersionConflict   RejectReason = "version_conflict"
	RejectUnsupportedFormat RejectReason = "unsupported_format"
)

// Rejected is a raw record that could not be normalized into a Component.
type Rejected struct {
	Reason RejectReason
	Detail string
	Source SourceRef
	Raw    string // verbatim raw record for test logs / reproduction
}

// Warning is a non-fatal normalization note for an accepted component.
type Warning struct {
	Code   string
	Detail string
	Source SourceRef
}

// Manifest is the normalized view of one parsed file.
type Manifest struct {
	Format     string
	File       string
	Components []Component
	Rejected   []Rejected
	Warnings   []Warning
}
