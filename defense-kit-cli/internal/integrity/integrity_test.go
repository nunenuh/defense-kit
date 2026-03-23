package integrity_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/integrity"
)

// ---------------------------------------------------------------------------
// DefaultPaths
// ---------------------------------------------------------------------------

func TestDefaultPaths_NotEmpty(t *testing.T) {
	paths := integrity.DefaultPaths()
	if len(paths) == 0 {
		t.Error("DefaultPaths() should return at least one path")
	}
	for _, p := range paths {
		if p == "" {
			t.Error("DefaultPaths() contains an empty string")
		}
	}
}

// ---------------------------------------------------------------------------
// InitDB
// ---------------------------------------------------------------------------

// TestInitDB_CreatesHashes verifies that InitDB walks a temporary directory,
// hashes the files it finds, and returns a populated IntegrityDB.
func TestInitDB_CreatesHashes(t *testing.T) {
	dir := t.TempDir()

	// Create a few test files with known content.
	files := map[string]string{
		"file_a.txt": "hello world",
		"file_b.txt": "another file",
		"sub/file_c.txt": "nested file",
	}

	for rel, content := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", rel, err)
		}
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}

	if len(db.Files) == 0 {
		t.Fatal("InitDB produced an empty database for a non-empty directory")
	}
	if db.Version == 0 {
		t.Error("IntegrityDB.Version should not be zero")
	}
	if db.CreatedAt.IsZero() {
		t.Error("IntegrityDB.CreatedAt should not be zero")
	}

	// Every file we created must appear in the database with a non-empty hash.
	for rel := range files {
		fullPath := filepath.Join(dir, rel)
		fh, ok := db.Files[fullPath]
		if !ok {
			t.Errorf("file %s not found in db", fullPath)
			continue
		}
		if fh.SHA256 == "" {
			t.Errorf("file %s has empty SHA256", fullPath)
		}
		if fh.Size == 0 {
			t.Errorf("file %s has zero size", fullPath)
		}
	}
}

// TestInitDB_SkipsNonExistentPaths verifies that InitDB does not error when
// given a mix of existing and non-existing paths.
func TestInitDB_SkipsNonExistentPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := integrity.InitDB([]string{dir, "/this/path/does/not/exist"})
	if err != nil {
		t.Errorf("InitDB should not error on non-existent paths, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CompareDB
// ---------------------------------------------------------------------------

// TestCompareDB_DetectsModifiedFile verifies that CompareDB reports a "modified"
// change when a file's content changes after the baseline was taken.
func TestCompareDB_DetectsModifiedFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(filePath, []byte("original content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create baseline.
	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	if _, ok := db.Files[filePath]; !ok {
		t.Fatalf("expected %s in db", filePath)
	}

	// Modify the file after the baseline.
	if err := os.WriteFile(filePath, []byte("tampered content"), 0o644); err != nil {
		t.Fatalf("WriteFile (modify): %v", err)
	}

	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB: %v", err)
	}

	if len(changes) == 0 {
		t.Fatal("expected at least one change for modified file, got none")
	}

	found := false
	for _, ch := range changes {
		if ch.Path == filePath && ch.Type == "modified" {
			found = true
			if ch.OldHash == "" {
				t.Error("IntegrityChange.OldHash should not be empty")
			}
			if ch.NewHash == "" {
				t.Error("IntegrityChange.NewHash should not be empty")
			}
			if ch.OldHash == ch.NewHash {
				t.Error("OldHash and NewHash should differ for a modified file")
			}
		}
	}
	if !found {
		t.Errorf("expected a 'modified' change for %s, got: %+v", filePath, changes)
	}
}

// TestCompareDB_DetectsRemovedFile verifies that CompareDB reports a "removed"
// change when a baseline file no longer exists.
func TestCompareDB_DetectsRemovedFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "delete_me.txt")
	if err := os.WriteFile(filePath, []byte("to be deleted"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	// Remove the file.
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB: %v", err)
	}

	found := false
	for _, ch := range changes {
		if ch.Path == filePath && ch.Type == "removed" {
			found = true
			if ch.OldHash == "" {
				t.Error("IntegrityChange.OldHash should not be empty for removed file")
			}
		}
	}
	if !found {
		t.Errorf("expected a 'removed' change for %s, got: %+v", filePath, changes)
	}
}

// TestCompareDB_NoChangesForUnmodifiedDB verifies that an unmodified filesystem
// produces no changes.
func TestCompareDB_NoChangesForUnmodifiedDB(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stable.txt"), []byte("stable"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for unmodified filesystem, got %d: %+v", len(changes), changes)
	}
}

// ---------------------------------------------------------------------------
// SaveDB / LoadDB
// ---------------------------------------------------------------------------

// TestSaveAndLoadDB verifies the round-trip serialisation of an IntegrityDB.
func TestSaveAndLoadDB(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(filePath, []byte("round-trip test"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create baseline.
	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	// Save.
	dbPath := filepath.Join(dir, "integrity.json")
	if err := integrity.SaveDB(dbPath, db); err != nil {
		t.Fatalf("SaveDB: %v", err)
	}

	// Verify the file exists.
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database file not created: %v", err)
	}

	// Load.
	loaded, err := integrity.LoadDB(dbPath)
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}

	if loaded.Version != db.Version {
		t.Errorf("Version mismatch: got %d, want %d", loaded.Version, db.Version)
	}
	if len(loaded.Files) != len(db.Files) {
		t.Errorf("Files count mismatch: got %d, want %d", len(loaded.Files), len(db.Files))
	}
	for path, orig := range db.Files {
		got, ok := loaded.Files[path]
		if !ok {
			t.Errorf("file %s missing from loaded db", path)
			continue
		}
		if got.SHA256 != orig.SHA256 {
			t.Errorf("SHA256 mismatch for %s: got %q, want %q", path, got.SHA256, orig.SHA256)
		}
	}
}

// TestLoadDB_ErrorOnMissingFile verifies that LoadDB returns an error for a
// non-existent path.
func TestLoadDB_ErrorOnMissingFile(t *testing.T) {
	_, err := integrity.LoadDB("/tmp/this_does_not_exist_defense_kit.json")
	if err == nil {
		t.Error("LoadDB should return an error for a missing file")
	}
}
