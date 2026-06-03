package check

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

type poetryLockfile struct {
	Package []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name    string       `toml:"name"`
	Version string       `toml:"version"`
	Source  poetrySource `toml:"source"`
}

type poetrySource struct {
	Type string `toml:"type"`
}

// ParsePoetryLockfile parses a poetry.lock file (TOML format).
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParsePoetryLockfile(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	var lockfile poetryLockfile
	// armis:ignore cwe:502 cwe:770 reason:toml.Unmarshal into a typed struct does not execute code; data is size-bounded by readLockfile and is the user's own lockfile, not untrusted data
	if err := toml.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing poetry.lock: %w", err)
	}

	var entries []PackageEntry
	for _, pkg := range lockfile.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}

		if shouldSkipPoetrySource(pkg.Source) {
			continue
		}

		entries = append(entries, PackageEntry{
			Name:    normalizePipName(pkg.Name),
			Version: pkg.Version,
		})
	}

	return entries, nil
}

func shouldSkipPoetrySource(source poetrySource) bool {
	switch strings.ToLower(source.Type) {
	case sourceTypeGit, sourceTypeDirectory, sourceTypeFile, sourceTypeURL:
		return true
	}
	return false
}
