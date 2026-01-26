# vex Development Roadmap

## Milestone 1: Foundation

- [x] Set up Go module and dependencies
- [x] Implement CLI framework with cobra
- [x] Create core scanner interface
- [x] Implement basic file walker (respects .gitignore)
- [x] Add terminal output formatting

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
- [ ] Integrate with OSV API for vulnerability lookup
- [ ] Cache vulnerability data

## Milestone 4: OpenVEX Integration

- [x] Implement OpenVEX document parser
- [x] Filter findings based on VEX statements
- [x] Implement VEX document generator
- [x] Add `vex generate` subcommand

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

## Milestone 7: Polish

- [ ] Add progress indicators
- [x] Implement configuration file (.vex.yaml)
- [ ] Add monorepo detection and per-project config
- [ ] Write comprehensive tests
- [ ] Documentation and examples

## Future Enhancements

- [ ] YAML configuration support
- [ ] Custom pattern definitions in config
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
