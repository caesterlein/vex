// Package secrets provides secret detection functionality.
package secrets

import "regexp"

// SecretPattern defines a pattern for detecting secrets.
type SecretPattern struct {
	// ID is a unique identifier for this pattern
	ID string

	// Name is a human-readable name
	Name string

	// Pattern is the compiled regex
	Pattern *regexp.Regexp

	// Description explains what this pattern detects
	Description string

	// Severity is the default severity for matches
	Severity string

	// Keywords are strings that must be present for the pattern to apply
	Keywords []string
}

// DefaultPatterns returns the built-in secret detection patterns.
func DefaultPatterns() []SecretPattern {
	return []SecretPattern{
		{
			ID:          "aws-access-key-id",
			Name:        "AWS Access Key ID",
			Pattern:     regexp.MustCompile(`\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`),
			Description: "AWS Access Key ID used for programmatic access to AWS services",
			Severity:    "critical",
		},
		{
			ID:          "aws-secret-access-key",
			Name:        "AWS Secret Access Key",
			Pattern:     regexp.MustCompile(`(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key[\s]*[=:]["']?\s*([A-Za-z0-9/+=]{40})`),
			Description: "AWS Secret Access Key provides full access to AWS resources",
			Severity:    "critical",
		},
		{
			ID:          "github-token",
			Name:        "GitHub Token",
			Pattern:     regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`),
			Description: "GitHub Personal Access Token or OAuth token",
			Severity:    "critical",
		},
		{
			ID:          "github-fine-grained-token",
			Name:        "GitHub Fine-Grained Token",
			Pattern:     regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`),
			Description: "GitHub Fine-Grained Personal Access Token",
			Severity:    "critical",
		},
		{
			ID:          "gitlab-token",
			Name:        "GitLab Token",
			Pattern:     regexp.MustCompile(`\bglpat-[A-Za-z0-9\-]{20,}\b`),
			Description: "GitLab Personal Access Token",
			Severity:    "critical",
		},
		{
			ID:          "slack-token",
			Name:        "Slack Token",
			Pattern:     regexp.MustCompile(`\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b`),
			Description: "Slack API token for bot or user access",
			Severity:    "high",
		},
		{
			ID:          "slack-webhook",
			Name:        "Slack Webhook URL",
			Pattern:     regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}`),
			Description: "Slack Incoming Webhook URL",
			Severity:    "medium",
		},
		{
			ID:          "stripe-secret-key",
			Name:        "Stripe Secret Key",
			Pattern:     regexp.MustCompile(`\bsk_(live|test)_[A-Za-z0-9]{24,}\b`),
			Description: "Stripe API secret key for payment processing",
			Severity:    "critical",
		},
		{
			ID:          "stripe-publishable-key",
			Name:        "Stripe Publishable Key",
			Pattern:     regexp.MustCompile(`\bpk_(live|test)_[A-Za-z0-9]{24,}\b`),
			Description: "Stripe publishable key (lower risk but should not be in code)",
			Severity:    "low",
		},
		{
			ID:          "google-api-key",
			Name:        "Google API Key",
			Pattern:     regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}\b`),
			Description: "Google Cloud API key",
			Severity:    "high",
		},
		{
			ID:          "google-oauth-client-secret",
			Name:        "Google OAuth Client Secret",
			Pattern:     regexp.MustCompile(`(?i)client[_\-\.]?secret["']?\s*[=:]\s*["']([A-Za-z0-9_-]{24})["']`),
			Description: "Google OAuth client secret",
			Severity:    "high",
			Keywords:    []string{"google", "oauth", "client"},
		},
		{
			ID:          "heroku-api-key",
			Name:        "Heroku API Key",
			Pattern:     regexp.MustCompile(`(?i)heroku[_\-\.]?api[_\-\.]?key[\s]*[=:]["']?\s*([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})`),
			Description: "Heroku API key for platform access",
			Severity:    "high",
		},
		{
			ID:          "twilio-api-key",
			Name:        "Twilio API Key",
			Pattern:     regexp.MustCompile(`\bSK[A-Za-z0-9]{32}\b`),
			Description: "Twilio API key for communication services",
			Severity:    "high",
		},
		{
			ID:          "sendgrid-api-key",
			Name:        "SendGrid API Key",
			Pattern:     regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
			Description: "SendGrid API key for email services",
			Severity:    "high",
		},
		{
			ID:          "npm-token",
			Name:        "NPM Access Token",
			Pattern:     regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
			Description: "NPM access token for package publishing",
			Severity:    "critical",
		},
		{
			ID:          "pypi-token",
			Name:        "PyPI API Token",
			Pattern:     regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}\b`),
			Description: "PyPI API token for package publishing",
			Severity:    "critical",
		},
		{
			ID:          "private-key",
			Name:        "Private Key",
			Pattern:     regexp.MustCompile(`-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----`),
			Description: "Private cryptographic key",
			Severity:    "critical",
		},
		{
			ID:          "generic-api-key",
			Name:        "Generic API Key",
			Pattern:     regexp.MustCompile(`(?i)(api[_\-\.]?key|apikey|api[_\-\.]?secret)[\s]*[=:]["']?\s*([A-Za-z0-9_\-]{20,})`),
			Description: "Generic API key pattern",
			Severity:    "medium",
		},
		{
			ID:          "generic-secret",
			Name:        "Generic Secret",
			Pattern:     regexp.MustCompile(`(?i)(secret|password|passwd|pwd|token|auth)[\s]*[=:]["']?\s*([A-Za-z0-9_\-!@#$%^&*]{8,})`),
			Description: "Generic secret or password assignment",
			Severity:    "medium",
		},
		{
			ID:          "jwt-token",
			Name:        "JSON Web Token",
			Pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b`),
			Description: "JSON Web Token (JWT) which may contain sensitive claims",
			Severity:    "medium",
		},
		{
			ID:          "basic-auth-header",
			Name:        "Basic Auth Header",
			Pattern:     regexp.MustCompile(`(?i)authorization[\s]*[=:]["']?\s*basic\s+[A-Za-z0-9+/=]{10,}`),
			Description: "HTTP Basic Authentication header with encoded credentials",
			Severity:    "high",
		},
		{
			ID:          "bearer-token",
			Name:        "Bearer Token",
			Pattern:     regexp.MustCompile(`(?i)authorization[\s]*[=:]["']?\s*bearer\s+[A-Za-z0-9_\-.]+`),
			Description: "HTTP Bearer token in authorization header",
			Severity:    "high",
		},
		{
			ID:          "database-url",
			Name:        "Database Connection URL",
			Pattern:     regexp.MustCompile(`(?i)(mysql|postgres|postgresql|mongodb|redis|amqp):\/\/[^:]+:[^@]+@[^\s"']+`),
			Description: "Database connection URL with embedded credentials",
			Severity:    "critical",
		},
	}
}

// TestFilePatterns returns patterns that indicate a file is a test fixture.
func TestFilePatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)_test\.`),
		regexp.MustCompile(`(?i)\.test\.`),
		regexp.MustCompile(`(?i)\.spec\.`),
		regexp.MustCompile(`(?i)test[_\-]?data`),
		regexp.MustCompile(`(?i)fixtures?`),
		regexp.MustCompile(`(?i)mocks?`),
		regexp.MustCompile(`(?i)fake[s]?`),
		regexp.MustCompile(`(?i)stub[s]?`),
		regexp.MustCompile(`(?i)example[s]?`),
		regexp.MustCompile(`(?i)sample[s]?`),
	}
}

// IsTestFile checks if a path appears to be a test file or fixture.
func IsTestFile(path string) bool {
	for _, pattern := range TestFilePatterns() {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}
