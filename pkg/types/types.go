// Package types provides shared types used across the vex scanner.
package types

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingType represents the category of a security finding.
type FindingType string

const (
	FindingTypeSecret     FindingType = "secret"
	FindingTypeDependency FindingType = "dependency"
	FindingTypeDocker     FindingType = "dockerfile"
)

// Finding represents a security issue discovered during scanning.
type Finding struct {
	// Type categorizes the finding (secret, dependency, dockerfile)
	Type FindingType `json:"type"`

	// RuleID is a unique identifier for the detection rule
	RuleID string `json:"rule_id"`

	// Title is a short description of the finding
	Title string `json:"title"`

	// Description provides detailed information about the finding
	Description string `json:"description"`

	// Severity indicates the risk level
	Severity Severity `json:"severity"`

	// Location contains file and line information
	Location Location `json:"location"`

	// Metadata contains type-specific additional data
	Metadata map[string]string `json:"metadata,omitempty"`

	// Suppressed indicates if this finding is suppressed by VEX
	Suppressed bool `json:"suppressed,omitempty"`

	// SuppressionReason explains why the finding was suppressed
	SuppressionReason string `json:"suppression_reason,omitempty"`
}

// Location represents where a finding was discovered.
type Location struct {
	// Path is the file path relative to the scan root
	Path string `json:"path"`

	// StartLine is the 1-indexed line number where the finding starts
	StartLine int `json:"start_line"`

	// EndLine is the 1-indexed line number where the finding ends
	EndLine int `json:"end_line"`

	// StartColumn is the 1-indexed column where the finding starts
	StartColumn int `json:"start_column,omitempty"`

	// EndColumn is the 1-indexed column where the finding ends
	EndColumn int `json:"end_column,omitempty"`

	// Snippet contains the relevant code snippet
	Snippet string `json:"snippet,omitempty"`
}

// ScanResult contains the results of a security scan.
type ScanResult struct {
	// Findings is the list of security issues found
	Findings []Finding `json:"findings"`

	// ScannedFiles is the count of files analyzed
	ScannedFiles int `json:"scanned_files"`

	// ScannedDependencies is the count of dependencies checked
	ScannedDependencies int `json:"scanned_dependencies,omitempty"`

	// Duration is how long the scan took in milliseconds
	Duration int64 `json:"duration_ms"`

	// Errors contains any non-fatal errors encountered
	Errors []string `json:"errors,omitempty"`
}

// Dependency represents a project dependency.
type Dependency struct {
	// Name is the package name
	Name string `json:"name"`

	// Version is the installed version
	Version string `json:"version"`

	// Ecosystem identifies the package manager (npm, go, pypi)
	Ecosystem string `json:"ecosystem"`

	// Path is the lockfile where this dependency was found
	Path string `json:"path"`

	// Direct indicates if this is a direct dependency
	Direct bool `json:"direct"`
}

// Vulnerability represents a known security vulnerability.
type Vulnerability struct {
	// ID is the vulnerability identifier (CVE, GHSA, etc.)
	ID string `json:"id"`

	// Aliases are alternative identifiers
	Aliases []string `json:"aliases,omitempty"`

	// Summary is a brief description
	Summary string `json:"summary"`

	// Severity is the assessed risk level
	Severity Severity `json:"severity"`

	// FixedVersion is the version that addresses this vulnerability
	FixedVersion string `json:"fixed_version,omitempty"`

	// References are URLs with more information
	References []string `json:"references,omitempty"`
}
