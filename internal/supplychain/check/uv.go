package check

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

type uvLockfile struct {
	Package []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name    string   `toml:"name"`
	Version string   `toml:"version"`
	Source  uvSource `toml:"source"`
}

type uvSource struct {
	Type string `toml:"type"`
}

// ParseUVLockfile parses a uv.lock file (TOML format).
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParseUVLockfile(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	var lockfile uvLockfile
	// armis:ignore cwe:502 cwe:770 reason:toml.Unmarshal into a typed struct does not execute code; data is size-bounded by readLockfile and is the user's own lockfile, not untrusted data
	if err := toml.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing uv.lock: %w", err)
	}

	var entries []PackageEntry
	for _, pkg := range lockfile.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}

		if shouldSkipUVSource(pkg.Source) {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    normalizePipName(pkg.Name),
			Version: pkg.Version,
		})
	}

	return entries, nil
}

// shouldSkipUVSource drops packages that do not resolve from a package index.
// A git/local/url dependency carries a lockfile version that has no meaning on
// PyPI, so querying PyPI for it would either 404 or match an unrelated
// same-named PyPI package and age-check the wrong artifact. Registry-backed
// packages have an empty (or registry) source type, so only the non-registry
// types are excluded — kept in sync with shouldSkipPDMSource.
func shouldSkipUVSource(source uvSource) bool {
	switch strings.ToLower(source.Type) {
	case sourceTypeGit, sourceTypePath, sourceTypeDirectory, sourceTypeFile, sourceTypeURL:
		return true
	}
	return false
}
