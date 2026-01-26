package deps

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/caesterlein/vex/pkg/types"
)

// PyPIParser parses requirements.txt files.
type PyPIParser struct{}

// Name returns the parser name.
func (p *PyPIParser) Name() string {
	return "pypi"
}

// CanParse returns true if this is a requirements file.
func (p *PyPIParser) CanParse(path string) bool {
	base := filepath.Base(path)
	return base == "requirements.txt" ||
		strings.HasPrefix(base, "requirements-") ||
		strings.HasSuffix(base, "-requirements.txt")
}

// Parse extracts dependencies from requirements.txt.
func (p *PyPIParser) Parse(path string, content []byte) ([]types.Dependency, error) {
	var deps []types.Dependency

	scanner := bufio.NewScanner(bytes.NewReader(content))

	// Regex for parsing requirement lines
	// Matches: package==1.0.0, package>=1.0.0, package~=1.0.0, etc.
	reqRegex := regexp.MustCompile(`^([a-zA-Z0-9][\w\-\.]*)(?:\[[\w,\-]+\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s;#]+)?`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip options (like -r, -e, --index-url)
		if strings.HasPrefix(line, "-") {
			continue
		}

		matches := reqRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		version := ""
		if len(matches) > 3 && matches[3] != "" {
			version = matches[3]
		}

		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "pypi",
			Path:      path,
			Direct:    true, // requirements.txt typically lists direct deps
		})
	}

	return deps, nil
}
