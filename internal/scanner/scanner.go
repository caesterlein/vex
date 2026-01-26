// Package scanner provides the core scanning interface and utilities.
package scanner

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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

// WalkFiles walks the directory tree and calls fn for each regular file.
func WalkFiles(root string, opts WalkOptions, fn func(path string, info fs.FileInfo) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
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
			return nil // Skip files we can't stat
		}

		// Check file size
		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			return nil
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
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, relPath); matched {
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
