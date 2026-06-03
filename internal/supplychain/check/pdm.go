package check

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

type pdmLockfile struct {
	Package []pdmPackage `toml:"package"`
}

type pdmPackage struct {
	Name    string    `toml:"name"`
	Version string    `toml:"version"`
	Source  pdmSource `toml:"source"`
}

type pdmSource struct {
	Type string `toml:"type"`
}

// ParsePDMLockfile parses a pdm.lock file (TOML format).
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParsePDMLockfile(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	var lockfile pdmLockfile
	// armis:ignore cwe:502 cwe:770 reason:toml.Unmarshal into a typed struct does not execute code; data is size-bounded by readLockfile and is the user's own lockfile, not untrusted data
	if err := toml.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing pdm.lock: %w", err)
	}

	var entries []PackageEntry
	for _, pkg := range lockfile.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}

		if shouldSkipPDMSource(pkg.Source) {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    normalizePipName(pkg.Name),
			Version: pkg.Version,
		})
	}

	return entries, nil
}

// shouldSkipPDMSource drops packages that do not resolve from a package index.
// A git/local/url dependency carries a lockfile version that has no meaning on
// PyPI, so querying PyPI for it would either 404 (silently warned away) or, worse,
// match an unrelated same-named PyPI package and age-check the wrong artifact.
// Index-backed packages have no source.type (or an explicit registry type), so
// only the non-registry types are excluded.
func shouldSkipPDMSource(source pdmSource) bool {
	switch strings.ToLower(source.Type) {
	case sourceTypeGit, sourceTypeVCS, sourceTypeDirectory, sourceTypePath, sourceTypeFile, sourceTypeURL:
		return true
	}
	return false
}
