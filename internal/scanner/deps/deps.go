// Package deps provides dependency vulnerability scanning.
package deps

import (
	"context"
	"os"
	"path/filepath"

	"github.com/caesterlein/vex/pkg/types"
)

// Scanner scans for dependency vulnerabilities.
type Scanner struct {
	parsers []Parser
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
func New() *Scanner {
	return &Scanner{
		parsers: []Parser{
			&NPMParser{},
			&GoModParser{},
			&PyPIParser{},
		},
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

	// Find all lockfiles
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			// Skip common non-source directories
			name := d.Name()
			if name == "node_modules" || name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
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

				// TODO: Check dependencies against vulnerability database (OSV)
				// For now, just track that we parsed dependencies
				_ = deps
			}
		}

		return nil
	})

	if err != nil {
		return result, err
	}

	return result, nil
}
