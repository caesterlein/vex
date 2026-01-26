package report

import (
	"fmt"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/caesterlein/vex/pkg/types"
)

// ToSARIF converts the report to SARIF format for CI integration.
func (r *Report) ToSARIF() (*sarif.Report, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, fmt.Errorf("creating sarif report: %w", err)
	}

	run := sarif.NewRunWithInformationURI("vex", "https://github.com/caesterlein/vex")

	// Add rules for each unique finding type
	rules := make(map[string]bool)

	for _, finding := range r.Findings {
		if finding.Suppressed {
			continue
		}

		// Add rule if not already added
		if !rules[finding.RuleID] {
			rule := run.AddRule(finding.RuleID).
				WithName(finding.Title).
				WithDescription(finding.Description).
				WithDefaultConfiguration(&sarif.ReportingConfiguration{
					Level: toSARIFLevel(finding.Severity),
				})

			// Add help text
			rule.WithHelp(&sarif.MultiformatMessageString{
				Text: &finding.Description,
			})

			rules[finding.RuleID] = true
		}

		// Add result
		result := sarif.NewRuleResult(finding.RuleID).
			WithLevel(toSARIFLevel(finding.Severity)).
			WithMessage(sarif.NewTextMessage(finding.Description))

		// Add location
		if finding.Location.Path != "" {
			loc := sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(finding.Location.Path))

			if finding.Location.StartLine > 0 {
				region := sarif.NewRegion().
					WithStartLine(finding.Location.StartLine).
					WithEndLine(finding.Location.EndLine)

				if finding.Location.StartColumn > 0 {
					region.WithStartColumn(finding.Location.StartColumn)
				}
				if finding.Location.EndColumn > 0 {
					region.WithEndColumn(finding.Location.EndColumn)
				}
				if finding.Location.Snippet != "" {
					region.WithSnippet(sarif.NewArtifactContent().WithText(finding.Location.Snippet))
				}

				loc.WithRegion(region)
			}

			result.WithLocations([]*sarif.Location{
				sarif.NewLocationWithPhysicalLocation(loc),
			})
		}

		run.AddResult(result)
	}

	report.AddRun(run)
	return report, nil
}

// WriteSARIF writes the report in SARIF format to a file.
func (r *Report) WriteSARIF(path string) error {
	sarifReport, err := r.ToSARIF()
	if err != nil {
		return err
	}

	return sarifReport.WriteFile(path)
}

func toSARIFLevel(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow, types.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
