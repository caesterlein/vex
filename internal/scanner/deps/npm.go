package deps

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/caesterlein/vex/pkg/types"
)

// NPMParser parses package-lock.json files.
type NPMParser struct{}

// Name returns the parser name.
func (p *NPMParser) Name() string {
	return "npm"
}

// CanParse returns true if this is a package-lock.json file.
func (p *NPMParser) CanParse(path string) bool {
	return filepath.Base(path) == "package-lock.json"
}

// packageLock represents the structure of package-lock.json.
type packageLock struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]packageInfo `json:"packages"`
	Dependencies    map[string]depInfo     `json:"dependencies"`
}

type packageInfo struct {
	Version   string            `json:"version"`
	Resolved  string            `json:"resolved"`
	Integrity string            `json:"integrity"`
	Dev       bool              `json:"dev"`
	Optional  bool              `json:"optional"`
	Requires  map[string]string `json:"requires"`
}

type depInfo struct {
	Version   string            `json:"version"`
	Resolved  string            `json:"resolved"`
	Integrity string            `json:"integrity"`
	Dev       bool              `json:"dev"`
	Optional  bool              `json:"optional"`
	Requires  map[string]string `json:"requires"`
}

// Parse extracts dependencies from package-lock.json.
func (p *NPMParser) Parse(path string, content []byte) ([]types.Dependency, error) {
	var lock packageLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}

	var deps []types.Dependency

	// Handle lockfile version 2/3 format (packages field)
	if lock.Packages != nil {
		for pkgPath, info := range lock.Packages {
			// Skip the root package
			if pkgPath == "" {
				continue
			}

			// Extract package name from path (e.g., "node_modules/@scope/pkg")
			name := strings.TrimPrefix(pkgPath, "node_modules/")
			if strings.Contains(name, "node_modules/") {
				// Nested dependency, get the last part
				parts := strings.Split(name, "node_modules/")
				name = parts[len(parts)-1]
			}

			deps = append(deps, types.Dependency{
				Name:      name,
				Version:   info.Version,
				Ecosystem: "npm",
				Path:      path,
				Direct:    !strings.Contains(pkgPath, "node_modules/node_modules/"),
			})
		}
	}

	// Handle lockfile version 1 format (dependencies field)
	if lock.Dependencies != nil && len(deps) == 0 {
		deps = p.parseDependenciesV1(lock.Dependencies, path, true)
	}

	return deps, nil
}

func (p *NPMParser) parseDependenciesV1(dependencies map[string]depInfo, lockfilePath string, direct bool) []types.Dependency {
	var deps []types.Dependency

	for name, info := range dependencies {
		deps = append(deps, types.Dependency{
			Name:      name,
			Version:   info.Version,
			Ecosystem: "npm",
			Path:      lockfilePath,
			Direct:    direct,
		})
	}

	return deps
}
