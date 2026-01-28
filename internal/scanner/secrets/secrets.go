package secrets

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/caesterlein/vex/internal/scanner"
	"github.com/caesterlein/vex/pkg/types"
)

// Scanner detects secrets in source code.
type Scanner struct {
	patterns      []SecretPattern
	skipTestFiles bool
	walkOptions   scanner.WalkOptions
	workers       int
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

// WithWalkOptions sets the walk options for file traversal.
func WithWalkOptions(opts scanner.WalkOptions) Option {
	return func(s *Scanner) {
		s.walkOptions = opts
	}
}

// WithWorkers sets the number of parallel workers (0 = auto-detect).
func WithWorkers(n int) Option {
	return func(s *Scanner) {
		s.workers = n
	}
}

// New creates a new secret scanner.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		patterns:      DefaultPatterns(),
		skipTestFiles: true,
		walkOptions:   scanner.DefaultWalkOptions(),
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

// Scan scans a directory for secrets using parallel workers.
func (s *Scanner) Scan(ctx context.Context, root string) (*types.ScanResult, error) {
	// Determine worker count
	workers := s.workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	// Shared result aggregation with mutex
	result := &types.ScanResult{
		Findings: []types.Finding{},
	}
	var mu sync.Mutex

	// Create file path channel
	fileCh := make(chan string, workers*2) // Buffered channel for smoother flow

	g, gctx := errgroup.WithContext(ctx)

	// Producer: walk files and send paths to channel
	g.Go(func() error {
		defer close(fileCh)

		walkOpts := s.walkOptions
		walkOpts.OnError = func(path string, err error) {
			mu.Lock()
			result.Errors = append(result.Errors, err.Error())
			mu.Unlock()
		}

		return scanner.WalkFiles(root, walkOpts, func(path string, info fs.FileInfo) error {
			select {
			case <-gctx.Done():
				return gctx.Err()
			case fileCh <- path:
				return nil
			}
		})
	})

	// Workers: process files from channel
	for i := 0; i < workers; i++ {
		g.Go(func() error {
			localFindings := []types.Finding{}
			localCount := 0

			for path := range fileCh {
				select {
				case <-gctx.Done():
					return gctx.Err()
				default:
				}

				if !s.ShouldScan(path) {
					continue
				}

				content, err := scanner.ReadFile(path, s.walkOptions.MaxFileSize)
				if err != nil || content == nil {
					continue
				}

				if !scanner.IsTextFile(content) {
					continue
				}

				findings, err := s.ScanFile(gctx, path, content)
				if err != nil {
					mu.Lock()
					result.Errors = append(result.Errors, err.Error())
					mu.Unlock()
					continue
				}

				localFindings = append(localFindings, findings...)
				localCount++
			}

			// Merge local results once at shutdown
			mu.Lock()
			result.Findings = append(result.Findings, localFindings...)
			result.ScannedFiles += localCount
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
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
				matchStart := match[0]
				matchEnd := match[1]

				if len(snippet) > 200 {
					start := matchStart - 50
					if start < 0 {
						start = 0
					}
					end := matchEnd + 50
					if end > len(snippet) {
						end = len(snippet)
					}
					snippet = snippet[start:end]
					// Adjust match indices to be relative to the truncated snippet
					matchStart -= start
					matchEnd -= start
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
						StartColumn: match[0] + 1, // Original line-relative position
						EndColumn:   match[1] + 1, // Original line-relative position
						Snippet:     maskSecret(snippet, matchStart, matchEnd),
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
	if end <= start || end > len(snippet) || start < 0 {
		// On boundary error, return fully masked snippet to avoid leaking secrets
		return strings.Repeat("*", len(snippet))
	}

	secretLen := end - start
	if secretLen <= 4 {
		// For very short secrets (1-4 chars), mask completely
		return snippet[:start] + strings.Repeat("*", secretLen) + snippet[end:]
	}
	if secretLen <= 8 {
		// For short secrets (5-8 chars), show first 2 and last 2 chars
		return snippet[:start+2] + strings.Repeat("*", secretLen-4) + snippet[end-2:]
	}

	// Show first 4 and last 4 chars of the secret
	masked := snippet[:start+4] + strings.Repeat("*", secretLen-8) + snippet[end-4:]
	return masked
}
