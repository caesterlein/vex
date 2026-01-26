// Package docker provides Dockerfile security scanning.
package docker

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/caesterlein/vex/pkg/types"
)

// Scanner scans Dockerfiles for security issues.
type Scanner struct{}

// New creates a new Docker scanner.
func New() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "docker"
}

// Scan scans a directory for Dockerfiles and checks for security issues.
func (s *Scanner) Scan(ctx context.Context, root string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Findings: []types.Finding{},
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a Dockerfile
		base := filepath.Base(path)
		if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
			content, err := os.ReadFile(path)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
				return nil
			}

			findings := s.scanDockerfile(path, content)
			result.Findings = append(result.Findings, findings...)
			result.ScannedFiles++
		}

		return nil
	})

	if err != nil {
		return result, err
	}

	return result, nil
}

func (s *Scanner) scanDockerfile(path string, content []byte) []types.Finding {
	var findings []types.Finding

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0
	var lastUser string
	hasUser := false

	// Patterns for detection
	secretEnvPattern := regexp.MustCompile(`(?i)(password|secret|token|api[_-]?key|private[_-]?key)`)
	unpinnedImagePattern := regexp.MustCompile(`^FROM\s+(\S+)$`)
	sensitiveCopyPattern := regexp.MustCompile(`(?i)COPY.*\.(pem|key|env|htpasswd|shadow|credentials)`)
	curlBashPattern := regexp.MustCompile(`(?i)(curl|wget).*\|\s*(bash|sh)`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		upperLine := strings.ToUpper(line)

		// Check for USER instruction
		if strings.HasPrefix(upperLine, "USER ") {
			hasUser = true
			lastUser = strings.TrimPrefix(line, "USER ")
			lastUser = strings.TrimPrefix(lastUser, "user ")
			lastUser = strings.TrimSpace(lastUser)
		}

		// Check for secrets in ENV or ARG
		if strings.HasPrefix(upperLine, "ENV ") || strings.HasPrefix(upperLine, "ARG ") {
			if secretEnvPattern.MatchString(line) {
				// Check if it's actually setting a value (not just declaring)
				if strings.Contains(line, "=") {
					findings = append(findings, types.Finding{
						Type:        types.FindingTypeDocker,
						RuleID:      "docker-secret-env",
						Title:       "Potential secret in Dockerfile",
						Description: "Secrets should not be hardcoded in Dockerfiles. Use build-time secrets or runtime environment variables instead.",
						Severity:    types.SeverityHigh,
						Location: types.Location{
							Path:      path,
							StartLine: lineNum,
							EndLine:   lineNum,
							Snippet:   line,
						},
					})
				}
			}
		}

		// Check for unpinned base images
		if strings.HasPrefix(upperLine, "FROM ") {
			matches := unpinnedImagePattern.FindStringSubmatch(line)
			if matches != nil {
				image := matches[1]
				// Check if image has a tag and if it's not 'latest'
				if !strings.Contains(image, ":") || strings.HasSuffix(image, ":latest") {
					// Also check it's not using a digest
					if !strings.Contains(image, "@sha256:") {
						findings = append(findings, types.Finding{
							Type:        types.FindingTypeDocker,
							RuleID:      "docker-unpinned-image",
							Title:       "Unpinned base image",
							Description: "Base images should be pinned to a specific version or digest for reproducible builds and security.",
							Severity:    types.SeverityMedium,
							Location: types.Location{
								Path:      path,
								StartLine: lineNum,
								EndLine:   lineNum,
								Snippet:   line,
							},
						})
					}
				}
			}
		}

		// Check for COPY of sensitive files
		if strings.HasPrefix(upperLine, "COPY ") || strings.HasPrefix(upperLine, "ADD ") {
			if sensitiveCopyPattern.MatchString(line) {
				findings = append(findings, types.Finding{
					Type:        types.FindingTypeDocker,
					RuleID:      "docker-sensitive-copy",
					Title:       "Copying potentially sensitive file",
					Description: "Sensitive files like private keys, .env files, or credentials should not be copied into Docker images.",
					Severity:    types.SeverityHigh,
					Location: types.Location{
						Path:      path,
						StartLine: lineNum,
						EndLine:   lineNum,
						Snippet:   line,
					},
				})
			}
		}

		// Check for curl | bash pattern
		if strings.HasPrefix(upperLine, "RUN ") {
			if curlBashPattern.MatchString(line) {
				findings = append(findings, types.Finding{
					Type:        types.FindingTypeDocker,
					RuleID:      "docker-curl-bash",
					Title:       "Curl piped to shell",
					Description: "Piping curl/wget directly to a shell is risky. Download scripts first, verify them, then execute.",
					Severity:    types.SeverityMedium,
					Location: types.Location{
						Path:      path,
						StartLine: lineNum,
						EndLine:   lineNum,
						Snippet:   line,
					},
				})
			}
		}
	}

	// Check if running as root (no USER instruction or last USER is root)
	if !hasUser || lastUser == "root" || lastUser == "0" {
		findings = append(findings, types.Finding{
			Type:        types.FindingTypeDocker,
			RuleID:      "docker-root-user",
			Title:       "Container runs as root",
			Description: "Containers should run as a non-root user. Add a USER instruction to switch to a non-privileged user.",
			Severity:    types.SeverityMedium,
			Location: types.Location{
				Path:      path,
				StartLine: 1,
				EndLine:   lineNum,
			},
		})
	}

	return findings
}
