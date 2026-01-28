// Package deps provides dependency vulnerability scanning.
package deps

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/caesterlein/vex/internal/scanner"
	"github.com/caesterlein/vex/pkg/types"
)

// Scanner scans for dependency vulnerabilities.
type Scanner struct {
	parsers    []Parser
	osvClient  *OSVClient
	walkOptions scanner.WalkOptions
}

// Parser is the interface for lockfile parsers.
type Parser interface {
	// Name returns the parser name
	Name() string

	// CanParse returns true if the parser can handle this file
	CanParse(path string) bool

	// Parse extracts dependencies from a lockfile
	Parse(path string, content []byte) ([]types.Dependency, error)
}

// New creates a new dependency scanner.
// If walkOpts is nil, DefaultWalkOptions() will be used.
func New(walkOpts ...scanner.WalkOptions) *Scanner {
	opts := scanner.DefaultWalkOptions()
	if len(walkOpts) > 0 {
		opts = walkOpts[0]
	}
	return &Scanner{
		parsers: []Parser{
			&NPMParser{},
			&GoModParser{},
			&PyPIParser{},
		},
		osvClient:  NewOSVClient(),
		walkOptions: opts,
	}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "dependencies"
}

// Scan scans a directory for dependencies and checks for vulnerabilities.
func (s *Scanner) Scan(ctx context.Context, root string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Findings: []types.Finding{},
	}

	// Collect all dependencies from all lockfiles
	allDeps := make([]types.Dependency, 0)

	// Configure error callback to collect walk errors
	walkOpts := s.walkOptions
	walkOpts.OnError = func(path string, err error) {
		result.Errors = append(result.Errors, err.Error())
	}

	// Find all lockfiles
	err := scanner.WalkFiles(root, walkOpts, func(path string, info fs.FileInfo) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		for _, parser := range s.parsers {
			if parser.CanParse(path) {
				content, err := os.ReadFile(path)
				if err != nil {
					result.Errors = append(result.Errors, err.Error())
					continue
				}

				deps, err := parser.Parse(path, content)
				if err != nil {
					result.Errors = append(result.Errors, err.Error())
					continue
				}

				result.ScannedDependencies += len(deps)
				result.ScannedFiles++

				// Collect dependencies for batch OSV query
				allDeps = append(allDeps, deps...)
			}
		}

		return nil
	})

	if err != nil {
		return result, err
	}

	// Query OSV API for vulnerabilities
	if len(allDeps) > 0 {
		batchResp, err := s.osvClient.QueryBatch(ctx, allDeps)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("OSV query failed: %v", err))
		} else {
			// Convert OSV vulnerabilities to findings
			for i, dep := range allDeps {
				if i < len(batchResp.Results) {
					queryResult := batchResp.Results[i]
					for _, vuln := range queryResult.Vulns {
						finding := convertVulnToFinding(vuln, dep)
						result.Findings = append(result.Findings, finding)
					}
				}
			}
		}
	}

	return result, nil
}
