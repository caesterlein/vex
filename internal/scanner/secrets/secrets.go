package secrets

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/caesterlein/vex/internal/scanner"
	"github.com/caesterlein/vex/pkg/types"
)

// Scanner detects secrets in source code.
type Scanner struct {
	patterns         []SecretPattern
	skipTestFiles    bool
	additionalIgnore []string
}

// Option configures the secret scanner.
type Option func(*Scanner)

// WithPatterns sets custom patterns.
func WithPatterns(patterns []SecretPattern) Option {
	return func(s *Scanner) {
		s.patterns = patterns
	}
}

// WithSkipTestFiles enables skipping test files.
func WithSkipTestFiles(skip bool) Option {
	return func(s *Scanner) {
		s.skipTestFiles = skip
	}
}

// New creates a new secret scanner.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		patterns:      DefaultPatterns(),
		skipTestFiles: true,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "secrets"
}

// ShouldScan returns true if this file should be scanned for secrets.
func (s *Scanner) ShouldScan(path string) bool {
	// Skip binary file extensions
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".svg": true, ".webp": true,
		".pdf": true, ".doc": true, ".docx": true,
		".zip": true, ".tar": true, ".gz": true, ".rar": true,
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
		".pyc": true, ".class": true, ".o": true,
	}
	if binaryExts[ext] {
		return false
	}

	// Skip test files if configured
	if s.skipTestFiles && IsTestFile(path) {
		return false
	}

	return true
}

// Scan scans a directory for secrets.
func (s *Scanner) Scan(ctx context.Context, root string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Findings: []types.Finding{},
	}

	opts := scanner.DefaultWalkOptions()
	err := scanner.WalkFiles(root, opts, func(path string, info fs.FileInfo) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !s.ShouldScan(path) {
			return nil
		}

		content, err := scanner.ReadFile(path, opts.MaxFileSize)
		if err != nil || content == nil {
			return nil
		}

		if !scanner.IsTextFile(content) {
			return nil
		}

		findings, err := s.ScanFile(ctx, path, content)
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			return nil
		}

		result.Findings = append(result.Findings, findings...)
		result.ScannedFiles++
		return nil
	})

	if err != nil {
		return result, err
	}

	return result, nil
}

// ScanFile scans a single file for secrets.
func (s *Scanner) ScanFile(ctx context.Context, path string, content []byte) ([]types.Finding, error) {
	var findings []types.Finding

	// Get relative path for display
	relPath := path

	// Scan line by line for better location reporting
	lineScanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0

	for lineScanner.Scan() {
		lineNum++
		line := lineScanner.Text()

		for _, pattern := range s.patterns {
			matches := pattern.Pattern.FindAllStringIndex(line, -1)
			if matches == nil {
				continue
			}

			// Check keywords if specified
			if len(pattern.Keywords) > 0 {
				hasKeyword := false
				lineLower := strings.ToLower(line)
				for _, kw := range pattern.Keywords {
					if strings.Contains(lineLower, strings.ToLower(kw)) {
						hasKeyword = true
						break
					}
				}
				if !hasKeyword {
					continue
				}
			}

			for _, match := range matches {
				// Mask the secret in the snippet
				snippet := line
				if len(snippet) > 200 {
					start := match[0] - 50
					if start < 0 {
						start = 0
					}
					end := match[1] + 50
					if end > len(snippet) {
						end = len(snippet)
					}
					snippet = snippet[start:end]
				}

				finding := types.Finding{
					Type:        types.FindingTypeSecret,
					RuleID:      pattern.ID,
					Title:       pattern.Name,
					Description: pattern.Description,
					Severity:    types.Severity(pattern.Severity),
					Location: types.Location{
						Path:        relPath,
						StartLine:   lineNum,
						EndLine:     lineNum,
						StartColumn: match[0] + 1,
						EndColumn:   match[1] + 1,
						Snippet:     maskSecret(snippet, match[0], match[1]),
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// maskSecret replaces the middle portion of a secret with asterisks.
func maskSecret(snippet string, start, end int) string {
	if end <= start || end > len(snippet) {
		return snippet
	}

	secretLen := end - start
	if secretLen <= 8 {
		// For short secrets, show first 2 and last 2 chars
		return snippet[:start+2] + "****" + snippet[end-2:]
	}

	// Show first 4 and last 4 chars of the secret
	masked := snippet[:start+4] + strings.Repeat("*", secretLen-8) + snippet[end-4:]
	return masked
}
