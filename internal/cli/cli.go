// Package cli provides the command-line interface for vex.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/caesterlein/vex/internal/config"
	"github.com/caesterlein/vex/internal/report"
	"github.com/caesterlein/vex/internal/scanner/deps"
	"github.com/caesterlein/vex/internal/scanner/docker"
	"github.com/caesterlein/vex/internal/scanner/secrets"
	"github.com/caesterlein/vex/internal/vex"
	"github.com/caesterlein/vex/pkg/types"
)

// Version is set at build time
var Version = "dev"

// Options holds CLI flags
type Options struct {
	ConfigFile  string
	OutputFormat string
	FailOn      string
	NoColor     bool
	NoVEX       bool
	SARIFOutput string
	Verbose     bool
}

var opts Options

// NewRootCmd creates the root cobra command.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "vex [path]",
		Short: "Unified security scanner for secrets, dependencies, and Dockerfiles",
		Long: `vex is a security scanner that detects:
  - Hardcoded secrets (API keys, tokens, passwords)
  - Vulnerable dependencies (via OSV database)
  - Dockerfile security issues

It supports OpenVEX for vulnerability suppression and outputs
in multiple formats including SARIF for CI integration.`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE:         runScan,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&opts.ConfigFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().StringVarP(&opts.OutputFormat, "format", "f", "terminal", "output format (terminal, json, sarif)")
	rootCmd.PersistentFlags().StringVar(&opts.FailOn, "fail-on", "high", "minimum severity to fail (critical, high, medium, low)")
	rootCmd.PersistentFlags().BoolVar(&opts.NoColor, "no-color", false, "disable colored output")
	rootCmd.PersistentFlags().BoolVar(&opts.NoVEX, "no-vex", false, "disable VEX suppression")
	rootCmd.PersistentFlags().StringVar(&opts.SARIFOutput, "sarif", "", "write SARIF output to file")
	rootCmd.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false, "verbose output")

	// Add subcommands
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newVexCmd())

	return rootCmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vex version %s\n", Version)
		},
	}
}

func newVexCmd() *cobra.Command {
	vexCmd := &cobra.Command{
		Use:   "vex",
		Short: "VEX document management",
	}

	generateCmd := &cobra.Command{
		Use:   "generate [path]",
		Short: "Generate a VEX template from scan findings",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runVexGenerate,
	}

	vexCmd.AddCommand(generateCmd)
	return vexCmd
}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine scan path
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	// Load config
	cfg := config.DefaultConfig()
	if opts.ConfigFile != "" {
		var err error
		cfg, err = config.Load(opts.ConfigFile)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
	} else if configPath, _ := config.FindConfig(scanPath); configPath != "" {
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
	}

	// Apply CLI overrides
	if opts.NoColor {
		cfg.Output.NoColor = true
	}
	if opts.OutputFormat != "" {
		cfg.Output.Format = opts.OutputFormat
	}

	ctx := context.Background()
	startTime := time.Now()

	var results []*types.ScanResult

	// Run secret scanner
	if cfg.Scanners.Secrets.Enabled {
		secretScanner := secrets.New(secrets.WithSkipTestFiles(cfg.Scanners.Secrets.SkipTests))
		result, err := secretScanner.Scan(ctx, scanPath)
		if err != nil {
			return fmt.Errorf("secret scan: %w", err)
		}
		results = append(results, result)
	}

	// Run dependency scanner
	if cfg.Scanners.Dependencies.Enabled {
		depScanner := deps.New()
		result, err := depScanner.Scan(ctx, scanPath)
		if err != nil {
			return fmt.Errorf("dependency scan: %w", err)
		}
		results = append(results, result)
	}

	// Run Docker scanner
	if cfg.Scanners.Docker.Enabled {
		dockerScanner := docker.New()
		result, err := dockerScanner.Scan(ctx, scanPath)
		if err != nil {
			return fmt.Errorf("docker scan: %w", err)
		}
		results = append(results, result)
	}

	// Aggregate results
	rpt := report.New(results...)
	rpt.Duration = time.Since(startTime).Milliseconds()

	// Apply VEX suppressions
	if cfg.VEX.Enabled && !opts.NoVEX {
		vexFiles, _ := vex.FindVexFiles(scanPath)
		if len(vexFiles) > 0 {
			var docs []*vex.Document
			for _, f := range vexFiles {
				doc, err := vex.ParseFile(f)
				if err == nil {
					docs = append(docs, doc)
				}
			}
			if len(docs) > 0 {
				filter := vex.NewFilter(docs)
				rpt.Findings = filter.Apply(rpt.Findings)
			}
		}
	}

	// Output results
	switch cfg.Output.Format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rpt); err != nil {
			return fmt.Errorf("encoding json: %w", err)
		}
	case "sarif":
		sarifReport, err := rpt.ToSARIF()
		if err != nil {
			return fmt.Errorf("generating sarif: %w", err)
		}
		if err := sarifReport.WriteFile("/dev/stdout"); err != nil {
			return fmt.Errorf("writing sarif: %w", err)
		}
	default:
		writer := report.NewTerminalWriter(os.Stdout, cfg.Output.NoColor)
		if err := writer.Write(rpt); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}

	// Write SARIF if requested
	if opts.SARIFOutput != "" {
		if err := rpt.WriteSARIF(opts.SARIFOutput); err != nil {
			return fmt.Errorf("writing sarif file: %w", err)
		}
	}

	// Determine exit code
	failSeverity := types.Severity(opts.FailOn)
	if rpt.HasFindingsAbove(failSeverity) {
		os.Exit(1)
	}

	return nil
}

func runVexGenerate(cmd *cobra.Command, args []string) error {
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	ctx := context.Background()

	// Run scans to get findings
	var results []*types.ScanResult

	secretScanner := secrets.New()
	if result, err := secretScanner.Scan(ctx, scanPath); err == nil {
		results = append(results, result)
	}

	depScanner := deps.New()
	if result, err := depScanner.Scan(ctx, scanPath); err == nil {
		results = append(results, result)
	}

	dockerScanner := docker.New()
	if result, err := dockerScanner.Scan(ctx, scanPath); err == nil {
		results = append(results, result)
	}

	rpt := report.New(results...)

	if len(rpt.Findings) == 0 {
		fmt.Println("No findings to generate VEX document for.")
		return nil
	}

	// Generate VEX template
	generator := vex.NewGenerator("security-team")
	doc := generator.GenerateTemplate(rpt.Findings)

	output, err := vex.ToJSON(doc)
	if err != nil {
		return fmt.Errorf("encoding vex document: %w", err)
	}

	fmt.Println(string(output))
	return nil
}

// Execute runs the CLI.
func Execute() error {
	return NewRootCmd().Execute()
}
