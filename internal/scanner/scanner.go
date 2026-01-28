// Package scanner provides the core scanning interface and utilities.
package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/caesterlein/vex/internal/config"
	"github.com/caesterlein/vex/pkg/types"
)

// Scanner is the interface that all scanners must implement.
type Scanner interface {
	// Name returns the scanner's identifier
	Name() string

	// Scan performs the security scan on the given path
	Scan(ctx context.Context, path string) (*types.ScanResult, error)
}

// FileScanner is a scanner that processes individual files.
type FileScanner interface {
	Scanner

	// ScanFile analyzes a single file and returns findings
	ScanFile(ctx context.Context, path string, content []byte) ([]types.Finding, error)

	// ShouldScan returns true if this scanner should process the file
	ShouldScan(path string) bool
}

// WalkOptions configures the file walker behavior.
type WalkOptions struct {
	// IgnorePatterns are glob patterns to skip
	IgnorePatterns []string

	// FollowSymlinks controls symlink behavior
	FollowSymlinks bool

	// MaxFileSize is the maximum file size to process in bytes
	MaxFileSize int64

	// IncludeHidden controls whether hidden files are scanned
	IncludeHidden bool

	// OnError is called when file walk encounters an error.
	// If nil, errors are silently skipped. Setting this allows
	// collecting non-fatal errors during traversal.
	OnError func(path string, err error)

	// OnProgress is called before processing each file.
	// If nil, no progress updates are reported.
	OnProgress func(path string)
}

// DefaultWalkOptions returns sensible defaults for walking.
func DefaultWalkOptions() WalkOptions {
	return WalkOptions{
		IgnorePatterns: []string{
			".git",
			"node_modules",
			"vendor",
			"__pycache__",
			".venv",
			"venv",
			"dist",
			"build",
			".next",
			".nuxt",
		},
		FollowSymlinks: false,
		MaxFileSize:    10 * 1024 * 1024, // 10MB
		IncludeHidden:  false,
	}
}

// WalkOptionsFromConfig creates WalkOptions from a Config, merging config ignore patterns
// with default ignore patterns. Duplicates are removed.
func WalkOptionsFromConfig(cfg *config.Config) WalkOptions {
	defaultOpts := DefaultWalkOptions()
	
	// Create a map to track seen patterns for deduplication
	seen := make(map[string]bool)
	merged := make([]string, 0, len(defaultOpts.IgnorePatterns)+len(cfg.Ignore))
	
	// Add default patterns first
	for _, pattern := range defaultOpts.IgnorePatterns {
		if !seen[pattern] {
			seen[pattern] = true
			merged = append(merged, pattern)
		}
	}
	
	// Add config patterns (avoiding duplicates)
	for _, pattern := range cfg.Ignore {
		if !seen[pattern] {
			seen[pattern] = true
			merged = append(merged, pattern)
		}
	}
	
	return WalkOptions{
		IgnorePatterns: merged,
		FollowSymlinks: defaultOpts.FollowSymlinks,
		MaxFileSize:    defaultOpts.MaxFileSize,
		IncludeHidden:  defaultOpts.IncludeHidden,
	}
}

// WalkFiles walks the directory tree and calls fn for each regular file.
func WalkFiles(root string, opts WalkOptions, fn func(path string, info fs.FileInfo) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Report walk errors via callback instead of aborting
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil // Skip this entry, continue walking
		}

		// Get relative path for pattern matching
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			relPath = path
		}

		// Check if should skip
		if shouldSkip(relPath, d.Name(), d.IsDir(), opts) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Only process regular files
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			// Report stat errors via callback
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil // Skip files we can't stat
		}

		// Check file size
		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			return nil
		}

		// Report progress if callback is set
		if opts.OnProgress != nil {
			opts.OnProgress(path)
		}

		return fn(path, info)
	})
}

// shouldSkip determines if a file or directory should be skipped.
func shouldSkip(relPath, name string, isDir bool, opts WalkOptions) bool {
	// Skip hidden files unless configured otherwise
	if !opts.IncludeHidden && strings.HasPrefix(name, ".") && name != "." {
		return true
	}

	// Check ignore patterns
	for _, pattern := range opts.IgnorePatterns {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			// Report malformed pattern errors via callback
			if opts.OnError != nil {
				opts.OnError(name, err)
			}
			continue
		}
		if matched {
			return true
		}

		matched, err = filepath.Match(pattern, relPath)
		if err != nil {
			// Report malformed pattern errors via callback
			if opts.OnError != nil {
				opts.OnError(relPath, err)
			}
			continue
		}
		if matched {
			return true
		}
	}

	return false
}

// ReadFile reads a file with size checking.
func ReadFile(path string, maxSize int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if maxSize > 0 && info.Size() > maxSize {
		return nil, nil
	}

	return os.ReadFile(path)
}

// IsTextFile does a simple check to determine if a file is text.
func IsTextFile(content []byte) bool {
	if len(content) == 0 {
		return true
	}

	// Check first 512 bytes for null bytes (binary indicator)
	checkLen := 512
	if len(content) < checkLen {
		checkLen = len(content)
	}

	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			return false
		}
	}

	return true
}
