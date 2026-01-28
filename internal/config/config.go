// Package config provides configuration loading for vex.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/caesterlein/vex/pkg/types"
	"gopkg.in/yaml.v3"
)

// Config holds the vex scanner configuration.
type Config struct {
	// Version is the config file version
	Version string `json:"version" yaml:"version"`

	// Scanners configures which scanners to run
	Scanners ScannersConfig `json:"scanners" yaml:"scanners"`

	// Ignore patterns for files/directories
	Ignore []string `json:"ignore" yaml:"ignore"`

	// FailOn sets the minimum severity to fail CI
	FailOn types.Severity `json:"fail_on" yaml:"fail_on"`

	// Output configures report output
	Output OutputConfig `json:"output" yaml:"output"`

	// VEX configures VEX document handling
	VEX VEXConfig `json:"vex" yaml:"vex"`

	// Workers sets the number of parallel workers (0 = auto-detect from CPU count)
	Workers int `json:"workers" yaml:"workers"`
}

// ScannersConfig controls scanner behavior.
type ScannersConfig struct {
	// Secrets configuration
	Secrets SecretsConfig `json:"secrets" yaml:"secrets"`

	// Dependencies configuration
	Dependencies DepsConfig `json:"dependencies" yaml:"dependencies"`

	// Docker configuration
	Docker DockerConfig `json:"docker" yaml:"docker"`
}

// SecretsConfig configures secret scanning.
type SecretsConfig struct {
	// Enabled controls whether to scan for secrets
	Enabled bool `json:"enabled" yaml:"enabled"`

	// SkipTests skips test files
	SkipTests bool `json:"skip_tests" yaml:"skip_tests"`

	// AdditionalPatterns are custom regex patterns
	AdditionalPatterns []PatternConfig `json:"additional_patterns" yaml:"additional_patterns"`

	// DisabledRules are rule IDs to skip
	DisabledRules []string `json:"disabled_rules" yaml:"disabled_rules"`
}

// PatternConfig defines a custom secret pattern.
type PatternConfig struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Pattern     string `json:"pattern" yaml:"pattern"`
	Description string `json:"description" yaml:"description"`
	Severity    string `json:"severity" yaml:"severity"`
}

// DepsConfig configures dependency scanning.
type DepsConfig struct {
	// Enabled controls whether to scan dependencies
	Enabled bool `json:"enabled" yaml:"enabled"`

	// IgnorePackages are package names to skip
	IgnorePackages []string `json:"ignore_packages" yaml:"ignore_packages"`

	// IgnoreVulns are vulnerability IDs to skip
	IgnoreVulns []string `json:"ignore_vulns" yaml:"ignore_vulns"`
}

// DockerConfig configures Dockerfile scanning.
type DockerConfig struct {
	// Enabled controls whether to scan Dockerfiles
	Enabled bool `json:"enabled" yaml:"enabled"`

	// DisabledRules are rule IDs to skip
	DisabledRules []string `json:"disabled_rules" yaml:"disabled_rules"`
}

// OutputConfig controls output formatting.
type OutputConfig struct {
	// Format is the output format (terminal, json, sarif)
	Format string `json:"format" yaml:"format"`

	// NoColor disables terminal colors
	NoColor bool `json:"no_color" yaml:"no_color"`

	// SARIFFile is the path for SARIF output
	SARIFFile string `json:"sarif_file" yaml:"sarif_file"`
}

// VEXConfig controls VEX document handling.
type VEXConfig struct {
	// Enabled controls whether to apply VEX suppressions
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Files are paths to VEX documents
	Files []string `json:"files" yaml:"files"`

	// AutoDiscover enables automatic VEX file discovery
	AutoDiscover bool `json:"auto_discover" yaml:"auto_discover"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: "1",
		Scanners: ScannersConfig{
			Secrets: SecretsConfig{
				Enabled:   true,
				SkipTests: true,
			},
			Dependencies: DepsConfig{
				Enabled: true,
			},
			Docker: DockerConfig{
				Enabled: true,
			},
		},
		Ignore: []string{
			".git",
			"node_modules",
			"vendor",
			"__pycache__",
			".venv",
		},
		FailOn: types.SeverityHigh,
		Output: OutputConfig{
			Format: "terminal",
		},
		VEX: VEXConfig{
			Enabled:      true,
			AutoDiscover: true,
		},
	}
}

// Load loads configuration from a file.
func Load(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := DefaultConfig()
	
	// Detect file format by extension
	ext := strings.ToLower(filepath.Ext(path))
	isYAML := ext == ".yaml" || ext == ".yml"
	
	if isYAML {
		if err := yaml.Unmarshal(content, config); err != nil {
			return nil, err
		}
	} else if ext == ".json" {
		if err := json.Unmarshal(content, config); err != nil {
			return nil, err
		}
	} else {
		// Try JSON first, then YAML as fallback
		if err := json.Unmarshal(content, config); err != nil {
			// If JSON fails, try YAML
			if yamlErr := yaml.Unmarshal(content, config); yamlErr != nil {
				return nil, err // Return original JSON error
			}
			// YAML succeeded, continue
		}
		// JSON succeeded, continue
	}

	return config, nil
}

// FindConfig looks for a config file in standard locations.
func FindConfig(root string) (string, error) {
	candidates := []string{
		".vex.json",
		".vex.yaml",
		".vex.yml",
		"vex.json",
		"vex.yaml",
		"vex.yml",
	}

	for _, name := range candidates {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", nil
}
