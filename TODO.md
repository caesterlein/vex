# vex Development Roadmap

*Last verified against codebase: 2026-01.*

## Milestone 1: Foundation

- [x] Set up Go module and dependencies
- [x] Implement CLI framework with cobra
- [x] Create core scanner interface
- [x] Implement basic file walker (respects .gitignore)
- [x] Add terminal output formatting
- [x] Config ignore patterns merged with WalkOptions (`WalkOptionsFromConfig`)

## Critical Issues (Resolved)

These were previously blocking but have been implemented.

- [x] Create `cmd/vex/main.go` entry point
- [x] Implement `internal/vex` package (OpenVEX parsing, filtering, generation)
  - [x] OpenVEX document parser (JSON/YAML)
  - [x] VEX file discovery (`FindVexFiles`)
  - [x] Finding filter based on VEX statements (`NewFilter`, `Apply`)
  - [x] VEX document generator (`NewGenerator`, `GenerateTemplate`)
  - [x] VEX JSON serialization (`ToJSON`)

## Milestone 2: Secret Detection

- [x] Define secret patterns (AWS, GitHub, generic API keys, etc.)
- [x] Implement regex-based secret scanner
- [ ] Add entropy analysis for high-confidence detection
- [x] Implement test file detection (reduce false positives)
- [ ] Add .vexignore support for exclusions

## Milestone 3: Dependency Scanning

- [x] Implement package-lock.json parser
- [x] Implement go.mod/go.sum parser
- [x] Implement requirements.txt parser
- [x] Integrate with OSV API for vulnerability lookup
- [x] Cache vulnerability data

## Milestone 4: OpenVEX Integration

- [x] Implement OpenVEX document parser
- [x] Filter findings based on VEX statements
- [x] Implement VEX document generator
- [x] Add `vex generate` subcommand (CLI exists; full command is `vex vex generate`)

## Milestone 5: Dockerfile Scanning

- [x] Parse Dockerfile instructions
- [x] Check for USER root issues
- [x] Detect hardcoded secrets in ENV/ARG
- [x] Check for pinned base image versions
- [x] Detect COPY of sensitive files

## Milestone 6: Output & CI

- [x] Implement SARIF output format
- [x] Add JSON output option
- [x] Add exit codes for CI (0 = clean, 1 = findings)
- [x] GitHub Actions integration example
- [x] Add --fail-on flag (critical, high, medium, low)

## Milestone 7: Testing ✓

- [x] Add unit tests for secret pattern matching (false positive/negative rates)
- [x] Add unit tests for dependency parsers (edge cases)
- [x] Add unit tests for VEX filtering logic (96.1% coverage)
- [x] Add unit tests for configuration loading (100% coverage)
- [x] Add unit tests for SARIF generation (98.8% coverage)
- [x] Set up CI test coverage reporting (Codecov integration)

## Milestone 8: Performance & Polish

- [x] Add parallel scan execution (concurrent file processing)
  - Implemented two-level parallelism using errgroup (2026-01-27)
  - Inter-scanner: secrets, deps, and docker scanners run concurrently
  - Intra-scanner: secrets scanner uses worker pool for concurrent file processing
  - Added --workers/-w flag (0 = auto-detect from CPU count)
  - Added Workers config field in .vex.json/.vex.yaml
  - Deterministic output via post-scan sorting by file path + line number
  - Race-free with mutex-protected result aggregation
- [x] Add progress indicators
  - Implemented TTY-aware spinner with file-by-file progress updates (2026-01-27)
  - Auto-detects terminal, no output pollution in CI/piped contexts
  - Thread-safe with proper goroutine synchronization
- [x] Implement configuration file (.vex.yaml)
- [x] Fix YAML configuration loading (struct has tags but only JSON works)
- [ ] Add monorepo detection and per-project config
  - Per-path config works via `FindConfig(scanPath)`; missing: monorepo detection, multi-project scan
- [ ] Documentation and examples

## Security Improvements

- [x] **Fixed critical secret masking bug** (2026-01-27)
  - Fixed index adjustment after snippet truncation for lines >200 chars
  - Fixed boundary error handling to mask rather than leak on invalid indices
  - Fixed short secret overlap for secrets ≤4 chars
  - Added comprehensive test coverage for edge cases
- [ ] Add VEX document validation
- [ ] Optimize regex performance (23 patterns compiled per scan)
- [ ] Review large file handling (10MB limit may skip important files)

## Code Quality & Bug Fixes

- [x] **Improved error handling for VEX parsing** (2026-01-27)
  - `LoadFromDirectory()` now returns parse errors alongside valid documents
  - CLI warns users about failed VEX files (verbose: per-file errors; always: summary)
  - `vex generate` warns about scanner failures in verbose mode
  - Parse errors include filename context for easier debugging
- [x] **Improved error handling for file walking** (2026-01-27)
  - Added `OnError` callback to `WalkOptions` for collecting non-fatal errors
  - Walk errors (permission denied) no longer abort entire scan, errors are accumulated
  - `d.Info()` failures and `filepath.Match` errors now reported via callback
  - All scanners (secrets, deps, docker) wire errors to `result.Errors`
  - Comprehensive test coverage for error scenarios

## Future Enhancements

- [ ] Custom pattern definitions in config
  - `AdditionalPatterns` / `PatternConfig` exist in config; wire to secrets scanner and document
- [ ] Git history scanning (detect secrets in past commits)
- [ ] Pre-commit hook integration
- [ ] VS Code extension
- [ ] Baseline file support (ignore existing findings)
- [ ] HTML report output
- [ ] Incremental scanning (only changed files)
- [ ] poetry.lock and Pipfile.lock parsers
- [ ] pnpm-lock.yaml parser
- [ ] Cargo.lock parser (Rust)
- [ ] composer.lock parser (PHP)
