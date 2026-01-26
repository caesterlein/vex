package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/caesterlein/vex/pkg/types"
)

// TerminalWriter outputs findings to the terminal with colors.
type TerminalWriter struct {
	out     io.Writer
	noColor bool
}

// NewTerminalWriter creates a terminal output writer.
func NewTerminalWriter(out io.Writer, noColor bool) *TerminalWriter {
	if noColor {
		color.NoColor = true
	}
	return &TerminalWriter{out: out, noColor: noColor}
}

// Write outputs the report to the terminal.
func (w *TerminalWriter) Write(r *Report) error {
	summary := r.GetSummary()

	// Group findings by type
	byType := r.FindingsByType()

	// Print findings by type
	typeOrder := []types.FindingType{
		types.FindingTypeSecret,
		types.FindingTypeDependency,
		types.FindingTypeDocker,
	}

	for _, ft := range typeOrder {
		findings := byType[ft]
		if len(findings) == 0 {
			continue
		}

		w.printTypeHeader(ft)

		for _, f := range findings {
			if f.Suppressed {
				continue
			}
			w.printFinding(f)
		}
		fmt.Fprintln(w.out)
	}

	// Print summary
	w.printSummary(r, summary)

	return nil
}

func (w *TerminalWriter) printTypeHeader(ft types.FindingType) {
	var title string
	switch ft {
	case types.FindingTypeSecret:
		title = "Secrets"
	case types.FindingTypeDependency:
		title = "Dependencies"
	case types.FindingTypeDocker:
		title = "Dockerfile Issues"
	}

	bold := color.New(color.Bold)
	bold.Fprintf(w.out, "\n%s\n", title)
	fmt.Fprintln(w.out, strings.Repeat("─", len(title)))
}

func (w *TerminalWriter) printFinding(f types.Finding) {
	// Severity indicator
	sevColor := w.severityColor(f.Severity)
	sevColor.Fprintf(w.out, "  [%s] ", strings.ToUpper(string(f.Severity)))

	// Title and location
	fmt.Fprintf(w.out, "%s\n", f.Title)

	// Location
	gray := color.New(color.FgHiBlack)
	if f.Location.Path != "" {
		gray.Fprintf(w.out, "         %s", f.Location.Path)
		if f.Location.StartLine > 0 {
			gray.Fprintf(w.out, ":%d", f.Location.StartLine)
		}
		fmt.Fprintln(w.out)
	}

	// Snippet
	if f.Location.Snippet != "" {
		snippet := strings.TrimSpace(f.Location.Snippet)
		if len(snippet) > 100 {
			snippet = snippet[:100] + "..."
		}
		gray.Fprintf(w.out, "         %s\n", snippet)
	}

	// Description (only if different from title)
	if f.Description != "" && f.Description != f.Title {
		gray.Fprintf(w.out, "         %s\n", f.Description)
	}
}

func (w *TerminalWriter) printSummary(r *Report, s Summary) {
	fmt.Fprintln(w.out)
	bold := color.New(color.Bold)
	bold.Fprintln(w.out, "Summary")
	fmt.Fprintln(w.out, strings.Repeat("─", 40))

	fmt.Fprintf(w.out, "  Files scanned:        %d\n", r.ScannedFiles)
	if r.ScannedDependencies > 0 {
		fmt.Fprintf(w.out, "  Dependencies checked: %d\n", r.ScannedDependencies)
	}

	fmt.Fprintln(w.out)
	fmt.Fprintln(w.out, "  Findings:")

	// Critical
	crit := color.New(color.FgRed, color.Bold)
	crit.Fprintf(w.out, "    Critical: %d\n", s.Critical)

	// High
	high := color.New(color.FgRed)
	high.Fprintf(w.out, "    High:     %d\n", s.High)

	// Medium
	med := color.New(color.FgYellow)
	med.Fprintf(w.out, "    Medium:   %d\n", s.Medium)

	// Low
	low := color.New(color.FgCyan)
	low.Fprintf(w.out, "    Low:      %d\n", s.Low)

	// Info
	info := color.New(color.FgBlue)
	info.Fprintf(w.out, "    Info:     %d\n", s.Info)

	if s.Suppressed > 0 {
		gray := color.New(color.FgHiBlack)
		gray.Fprintf(w.out, "    Suppressed (VEX): %d\n", s.Suppressed)
	}

	// Total active findings
	active := s.Total - s.Suppressed
	fmt.Fprintln(w.out)
	if active == 0 {
		green := color.New(color.FgGreen, color.Bold)
		green.Fprintln(w.out, "  No security issues found!")
	} else {
		bold.Fprintf(w.out, "  Total: %d finding(s)\n", active)
	}

	if len(r.Errors) > 0 {
		fmt.Fprintln(w.out)
		yellow := color.New(color.FgYellow)
		yellow.Fprintf(w.out, "  Warnings: %d error(s) during scan\n", len(r.Errors))
	}
}

func (w *TerminalWriter) severityColor(s types.Severity) *color.Color {
	switch s {
	case types.SeverityCritical:
		return color.New(color.FgRed, color.Bold)
	case types.SeverityHigh:
		return color.New(color.FgRed)
	case types.SeverityMedium:
		return color.New(color.FgYellow)
	case types.SeverityLow:
		return color.New(color.FgCyan)
	case types.SeverityInfo:
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}
