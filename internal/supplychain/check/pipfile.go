package check

import (
	"encoding/json"
	"fmt"
	"strings"
)

type pipfileLock struct {
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string `json:"version"`
}

// ParsePipfileLock parses a Pipfile.lock (JSON format from pipenv).
// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
func ParsePipfileLock(path string) ([]PackageEntry, error) {
	// armis:ignore cwe:22 cwe:23 cwe:73 reason:local CLI reading the user's own lockfile; path is from local detection or an explicit --lockfile flag, not untrusted input crossing a trust boundary
	data, err := readLockfile(path)
	if err != nil {
		return nil, err
	}

	var lockfile pipfileLock
	// armis:ignore cwe:770 cwe:502 reason:data is size-bounded by readLockfile and unmarshalled into a typed struct from the user's own lockfile; no untrusted-data deserialization risk
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("parsing Pipfile.lock: %w", err)
	}

	seen := make(map[string]bool)
	var entries []PackageEntry

	for name, pkg := range lockfile.Default {
		entry := pipfileEntryToPackage(name, pkg)
		if entry != nil && !seen[entry.Name+"@"+entry.Version] {
			seen[entry.Name+"@"+entry.Version] = true
			entries = append(entries, *entry)
		}
	}

	for name, pkg := range lockfile.Develop {
		entry := pipfileEntryToPackage(name, pkg)
		if entry != nil && !seen[entry.Name+"@"+entry.Version] {
			seen[entry.Name+"@"+entry.Version] = true
			entries = append(entries, *entry)
		}
	}

	return entries, nil
}

func pipfileEntryToPackage(name string, pkg pipfilePackage) *PackageEntry {
	version := pkg.Version
	if version == "" {
		return nil
	}

	// Strip == prefix
	version = strings.TrimPrefix(version, "==")
	if version == "" {
		return nil
	}

	// Skip non-pinned versions
	if strings.ContainsAny(version, "><!~*") {
		return nil
	}

	normalized := normalizePipName(name)
	return &PackageEntry{
		Name:    normalized,
		Version: version,
	}
}
