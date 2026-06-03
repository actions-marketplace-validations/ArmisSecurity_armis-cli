package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLockfile(t *testing.T) {
	t.Run("reads small file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package-lock.json")
		want := []byte(`{"lockfileVersion":3}`)
		if err := os.WriteFile(path, want, 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}

		got, err := readLockfile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(want) {
			t.Errorf("readLockfile = %q, want %q", got, want)
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		_, err := readLockfile(filepath.Join(t.TempDir(), "does-not-exist.json"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("file too large", func(t *testing.T) {
		// A lockfile larger than maxLockfileSize must fail with a clear "too
		// large" error rather than being silently truncated and surfacing as a
		// confusing JSON/YAML parse error. Truncate creates a sparse file so the
		// oversize size is recorded without writing 64MB to disk.
		dir := t.TempDir()
		path := filepath.Join(dir, "package-lock.json")
		f, err := os.Create(path) //nolint:gosec // path is test-scoped under t.TempDir()
		if err != nil {
			t.Fatalf("create fixture: %v", err)
		}
		if err := f.Truncate(maxLockfileSize + 1); err != nil {
			f.Close() //nolint:errcheck,gosec
			t.Fatalf("truncate fixture: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close fixture: %v", err)
		}

		_, err = readLockfile(path)
		if err == nil {
			t.Fatal("expected error for oversized lockfile")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("expected 'too large' error, got: %v", err)
		}
	})
}
