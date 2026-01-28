# vex

A unified security scanner for detecting secrets, vulnerable dependencies, and Dockerfile issues.

## Features

- **Secret Detection** - Find hardcoded API keys, tokens, passwords, and other credentials
- **Dependency Scanning** - Check npm, Go, and Python dependencies for known vulnerabilities
- **Dockerfile Analysis** - Detect security misconfigurations in container definitions
- **OpenVEX Support** - Suppress false positives with industry-standard VEX documents
- **CI Integration** - SARIF output for GitHub Code Scanning and other tools
- **Per-directory configuration** - Run vex in each project of a monorepo; config is loaded from the scanned path (`.vex.json` / `.vex.yaml`)

## Installation

### Using Go

```bash
go install github.com/caesterlein/vex/cmd/vex@latest
```

### From Source

```bash
git clone https://github.com/caesterlein/vex.git
cd vex
make install
```

### Binary Releases

Download pre-built binaries from the [releases page](https://github.com/caesterlein/vex/releases).

## Quick Start

```bash
# Scan current directory
vex

# Scan a specific path
vex ./my-project

# Output as JSON
vex --format json

# Generate SARIF for CI
vex --sarif results.sarif

# Fail on medium or higher severity
vex --fail-on medium
```

## Configuration

Create a `.vex.json` or `.vex.yaml` file in your project root:

```json
{
  "version": "1",
  "scanners": {
    "secrets": {
      "enabled": true,
      "skip_tests": true
    },
    "dependencies": {
      "enabled": true
    },
    "docker": {
      "enabled": true
    }
  },
  "ignore": [
    "node_modules",
    "vendor",
    ".git"
  ],
  "fail_on": "high"
}
```

## CI Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install vex
        run: go install github.com/caesterlein/vex/cmd/vex@latest

      - name: Run security scan
        run: vex --sarif results.sarif --fail-on high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

## OpenVEX Workflow

When vex finds a vulnerability that doesn't apply to your project, you can suppress it using a VEX document:

1. Generate a VEX template from current findings:
   ```bash
   vex vex generate > .vex.json
   ```

2. Edit the document to set appropriate status and justification:
   ```json
   {
     "@context": "https://openvex.dev/ns/v0.2.0",
     "statements": [
       {
         "vulnerability": "CVE-2023-1234",
         "status": "not_affected",
         "justification": "vulnerable_code_not_in_execute_path",
         "impact_statement": "The vulnerable function is never called in our usage"
       }
     ]
   }
   ```

3. Run vex again - the suppressed finding will be marked but won't fail CI:
   ```bash
   vex --fail-on high
   ```

### VEX Status Values

| Status | Description |
|--------|-------------|
| `not_affected` | The product is not affected by the vulnerability |
| `affected` | The product is affected and action should be taken |
| `fixed` | The vulnerability has been remediated |
| `under_investigation` | Analysis is in progress |

### Justifications (for not_affected)

| Justification | Description |
|---------------|-------------|
| `component_not_present` | The vulnerable component is not in the product |
| `vulnerable_code_not_present` | The vulnerable code was removed or never included |
| `vulnerable_code_not_in_execute_path` | The code exists but is never executed |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Inputs are sanitized/validated |
| `inline_mitigations_already_exist` | Other controls prevent exploitation |

## Secret Patterns

vex detects secrets from:
- AWS (Access Keys, Secret Keys)
- GitHub (Personal Access Tokens, OAuth Tokens)
- GitLab (Personal Access Tokens)
- Slack (Bot Tokens, Webhooks)
- Stripe (Secret Keys, Publishable Keys)
- Google Cloud (API Keys)
- Heroku (API Keys)
- Twilio (API Keys)
- SendGrid (API Keys)
- NPM (Access Tokens)
- PyPI (API Tokens)
- Private Keys (RSA, DSA, EC, etc.)
- Generic API keys and secrets
- Database connection strings
- JWT tokens
- Basic/Bearer auth headers

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the fail threshold |
| 1 | Findings found at or above the fail threshold |

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.
