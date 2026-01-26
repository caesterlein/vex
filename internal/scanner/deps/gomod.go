package deps

import (
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/caesterlein/vex/pkg/types"
)

// GoModParser parses go.mod files.
type GoModParser struct{}

// Name returns the parser name.
func (p *GoModParser) Name() string {
	return "go"
}

// CanParse returns true if this is a go.mod file.
func (p *GoModParser) CanParse(path string) bool {
	return filepath.Base(path) == "go.mod"
}

// Parse extracts dependencies from go.mod.
func (p *GoModParser) Parse(path string, content []byte) ([]types.Dependency, error) {
	f, err := modfile.Parse(path, content, nil)
	if err != nil {
		return nil, err
	}

	var deps []types.Dependency

	// Direct dependencies from require blocks
	for _, req := range f.Require {
		deps = append(deps, types.Dependency{
			Name:      req.Mod.Path,
			Version:   strings.TrimPrefix(req.Mod.Version, "v"),
			Ecosystem: "go",
			Path:      path,
			Direct:    !req.Indirect,
		})
	}

	return deps, nil
}
