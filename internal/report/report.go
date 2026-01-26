// Package report provides finding aggregation and output formatting.
package report

import (
	"sort"

	"github.com/caesterlein/vex/pkg/types"
)

// Report aggregates scan results and provides summary statistics.
type Report struct {
	Findings            []types.Finding
	ScannedFiles        int
	ScannedDependencies int
	Duration            int64
	Errors              []string
}

// New creates a new report from scan results.
func New(results ...*types.ScanResult) *Report {
	r := &Report{
		Findings: []types.Finding{},
	}

	for _, result := range results {
		if result == nil {
			continue
		}
		r.Findings = append(r.Findings, result.Findings...)
		r.ScannedFiles += result.ScannedFiles
		r.ScannedDependencies += result.ScannedDependencies
		r.Duration += result.Duration
		r.Errors = append(r.Errors, result.Errors...)
	}

	// Sort findings by severity, then by file path
	sort.Slice(r.Findings, func(i, j int) bool {
		si := severityOrder(r.Findings[i].Severity)
		sj := severityOrder(r.Findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return r.Findings[i].Location.Path < r.Findings[j].Location.Path
	})

	return r
}

// Summary returns a summary of findings by severity.
type Summary struct {
	Total      int
	Critical   int
	High       int
	Medium     int
	Low        int
	Info       int
	Suppressed int
}

// GetSummary returns finding counts by severity.
func (r *Report) GetSummary() Summary {
	s := Summary{Total: len(r.Findings)}

	for _, f := range r.Findings {
		if f.Suppressed {
			s.Suppressed++
			continue
		}

		switch f.Severity {
		case types.SeverityCritical:
			s.Critical++
		case types.SeverityHigh:
			s.High++
		case types.SeverityMedium:
			s.Medium++
		case types.SeverityLow:
			s.Low++
		case types.SeverityInfo:
			s.Info++
		}
	}

	return s
}

// ActiveFindings returns findings that are not suppressed.
func (r *Report) ActiveFindings() []types.Finding {
	var active []types.Finding
	for _, f := range r.Findings {
		if !f.Suppressed {
			active = append(active, f)
		}
	}
	return active
}

// FindingsByType returns findings grouped by type.
func (r *Report) FindingsByType() map[types.FindingType][]types.Finding {
	byType := make(map[types.FindingType][]types.Finding)
	for _, f := range r.Findings {
		byType[f.Type] = append(byType[f.Type], f)
	}
	return byType
}

// FindingsBySeverity returns findings grouped by severity.
func (r *Report) FindingsBySeverity() map[types.Severity][]types.Finding {
	bySev := make(map[types.Severity][]types.Finding)
	for _, f := range r.Findings {
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}
	return bySev
}

// HasFindingsAbove returns true if there are unsuppressed findings at or above the given severity.
func (r *Report) HasFindingsAbove(minSeverity types.Severity) bool {
	minOrder := severityOrder(minSeverity)
	for _, f := range r.Findings {
		if f.Suppressed {
			continue
		}
		if severityOrder(f.Severity) <= minOrder {
			return true
		}
	}
	return false
}

func severityOrder(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 0
	case types.SeverityHigh:
		return 1
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 3
	case types.SeverityInfo:
		return 4
	default:
		return 5
	}
}
