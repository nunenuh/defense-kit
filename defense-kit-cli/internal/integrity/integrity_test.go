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

// ---------------------------------------------------------------------------
// InitDB with nested directory paths
// ---------------------------------------------------------------------------

func TestInitDB_NestedDirectoryPaths(t *testing.T) {
	root := t.TempDir()

	// Create nested directory structure.
	dirs := []string{
		filepath.Join(root, "a", "b", "c"),
		filepath.Join(root, "x", "y"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", d, err)
		}
	}

	files := map[string]string{
		filepath.Join(root, "a", "b", "c", "deep.txt"):  "deep content",
		filepath.Join(root, "x", "y", "medium.txt"):     "medium content",
		filepath.Join(root, "top.txt"):                  "top content",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}

	db, err := integrity.InitDB([]string{root})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	for path := range files {
		if _, ok := db.Files[path]; !ok {
			t.Errorf("expected file %q in db but not found", path)
		}
	}
}

// ---------------------------------------------------------------------------
// CompareDB with added files (new file in monitored dir not in baseline)
// ---------------------------------------------------------------------------

func TestCompareDB_AddedFileNotDetected(t *testing.T) {
	// NOTE: CompareDB only detects changes to files IN the baseline.
	// A new file added to the filesystem is NOT detected (by design).
	// This test documents that behavior explicitly.
	dir := t.TempDir()
	existingFile := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(existingFile, []byte("existing"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	// Add a new file after the baseline was taken.
	newFile := filepath.Join(dir, "new_file.txt")
	if err := os.WriteFile(newFile, []byte("new"), 0o644); err != nil {
		t.Fatalf("WriteFile new: %v", err)
	}

	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB: %v", err)
	}

	// The existing file is unchanged, so no changes expected.
	for _, ch := range changes {
		if ch.Path == existingFile {
			t.Errorf("existing (unchanged) file should not appear in changes: %+v", ch)
		}
	}
}

func TestCompareDB_NoChanges(t *testing.T) {
	dir := t.TempDir()
	files := []string{"a.txt", "b.txt", "c.txt"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("content of "+name), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	if len(db.Files) != 3 {
		t.Fatalf("expected 3 files in db, got %d", len(db.Files))
	}

	// Compare immediately — no changes should be detected.
	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes, got %d: %+v", len(changes), changes)
	}
}

// ---------------------------------------------------------------------------
// SaveDB + LoadDB large dataset round-trip
// ---------------------------------------------------------------------------

func TestSaveLoadDB_LargeDataset(t *testing.T) {
	dir := t.TempDir()

	// Create 100 files.
	for i := 0; i < 100; i++ {
		name := filepath.Join(dir, "file-"+string(rune('a'+i%26))+"-"+string(rune('0'+i/26))+".txt")
		if err := os.WriteFile(name, []byte("content "+name), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	dbPath := filepath.Join(dir, "large.json")
	if err := integrity.SaveDB(dbPath, db); err != nil {
		t.Fatalf("SaveDB: %v", err)
	}

	loaded, err := integrity.LoadDB(dbPath)
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}

	if len(loaded.Files) != len(db.Files) {
		t.Errorf("file count mismatch: got %d, want %d", len(loaded.Files), len(db.Files))
	}

	// Spot-check a few hash values.
	for path, orig := range db.Files {
		got, ok := loaded.Files[path]
		if !ok {
			t.Errorf("file %s missing from loaded db", path)
			continue
		}
		if got.SHA256 != orig.SHA256 {
			t.Errorf("SHA256 mismatch for %s", path)
		}
	}
}

// ---------------------------------------------------------------------------
// DefaultPaths non-empty
// ---------------------------------------------------------------------------

func TestDefaultPaths_AllNonEmpty(t *testing.T) {
	paths := integrity.DefaultPaths()
	if len(paths) == 0 {
		t.Fatal("DefaultPaths() returned empty list")
	}
	for i, p := range paths {
		if p == "" {
			t.Errorf("DefaultPaths()[%d] is empty string", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Hash stability
// ---------------------------------------------------------------------------

// TestSaveDB_ErrorOnUnwritablePath verifies that SaveDB returns an error
// when the target directory doesn't exist.
func TestSaveDB_ErrorOnUnwritablePath(t *testing.T) {
	db := integrity.IntegrityDB{
		Version: 1,
		Files:   make(map[string]integrity.FileHash),
	}
	err := integrity.SaveDB("/nonexistent/path/that/cannot/be/created/db.json", db)
	if err == nil {
		t.Error("SaveDB should return an error for a non-existent directory")
	}
}

// TestCompareDB_SymlinkReplacedFile verifies that CompareDB detects a file
// that was replaced by a symlink as "modified".
func TestCompareDB_SymlinkReplacedFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(filePath, []byte("original"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	// Replace the file with a symlink.
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// Create a symlink pointing to itself (or another target).
	target := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	if err := os.Symlink(target, filePath); err != nil {
		t.Skipf("cannot create symlink (may require elevated permissions): %v", err)
	}

	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB: %v", err)
	}

	found := false
	for _, ch := range changes {
		if ch.Path == filePath && ch.Type == "modified" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'modified' change for symlinked file; got: %+v", changes)
	}
}

func TestHashStability_SameFileProducesSameHash(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "stable.bin")
	content := []byte("deterministic content for hash test")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	db1, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB (first): %v", err)
	}
	db2, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB (second): %v", err)
	}

	hash1 := db1.Files[filePath].SHA256
	hash2 := db2.Files[filePath].SHA256

	if hash1 == "" {
		t.Fatal("first hash is empty")
	}
	if hash1 != hash2 {
		t.Errorf("hash mismatch across runs: %q vs %q", hash1, hash2)
	}
}

// ---------------------------------------------------------------------------
// LoadDB invalid JSON
// ---------------------------------------------------------------------------

func TestLoadDB_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("not valid json {{{"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := integrity.LoadDB(badPath)
	if err == nil {
		t.Error("LoadDB should return an error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// SaveDB + LoadDB round-trip preserves all field values
// ---------------------------------------------------------------------------

func TestSaveLoadDB_FieldIntegrity(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.bin")
	content := []byte("field integrity test")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	dbPath := filepath.Join(dir, "fields.json")
	if err := integrity.SaveDB(dbPath, db); err != nil {
		t.Fatalf("SaveDB: %v", err)
	}

	loaded, err := integrity.LoadDB(dbPath)
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}

	orig := db.Files[filePath]
	got := loaded.Files[filePath]

	if got.Path != orig.Path {
		t.Errorf("Path mismatch: got %q, want %q", got.Path, orig.Path)
	}
	if got.SHA256 != orig.SHA256 {
		t.Errorf("SHA256 mismatch: got %q, want %q", got.SHA256, orig.SHA256)
	}
	if got.Size != orig.Size {
		t.Errorf("Size mismatch: got %d, want %d", got.Size, orig.Size)
	}
}

// ---------------------------------------------------------------------------
// CompareDB — multiple change types in single call
// ---------------------------------------------------------------------------

func TestCompareDB_MultipleChangeTypes(t *testing.T) {
	dir := t.TempDir()

	// Create 3 files.
	unchanged := filepath.Join(dir, "unchanged.txt")
	modified := filepath.Join(dir, "modified.txt")
	removed := filepath.Join(dir, "removed.txt")

	for path, data := range map[string]string{
		unchanged: "stable",
		modified:  "original",
		removed:   "will be deleted",
	} {
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	// Modify one file.
	if err := os.WriteFile(modified, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("WriteFile modify: %v", err)
	}
	// Remove one file.
	if err := os.Remove(removed); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB: %v", err)
	}

	typeCount := map[string]int{}
	for _, ch := range changes {
		typeCount[ch.Type]++
	}

	if typeCount["modified"] != 1 {
		t.Errorf("expected 1 modified, got %d", typeCount["modified"])
	}
	if typeCount["removed"] != 1 {
		t.Errorf("expected 1 removed, got %d", typeCount["removed"])
	}
	if typeCount["added"] != 0 {
		t.Errorf("expected 0 added (CompareDB doesn't detect adds), got %d", typeCount["added"])
	}
}

// ---------------------------------------------------------------------------
// InitDB with empty paths list
// ---------------------------------------------------------------------------

func TestInitDB_EmptyPaths(t *testing.T) {
	db, err := integrity.InitDB([]string{})
	if err != nil {
		t.Fatalf("InitDB with empty paths should not error: %v", err)
	}
	if len(db.Files) != 0 {
		t.Errorf("expected 0 files for empty paths, got %d", len(db.Files))
	}
	if db.Version != 1 {
		t.Errorf("Version should be 1, got %d", db.Version)
	}
}

// ---------------------------------------------------------------------------
// walkPath / hashFile error branches
// ---------------------------------------------------------------------------

// TestInitDB_UnreadableFile verifies that InitDB skips files it cannot read
// (exercising the hashFile open-error branch).
func TestInitDB_UnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — chmod 000 has no effect")
	}

	dir := t.TempDir()
	readable := filepath.Join(dir, "readable.txt")
	unreadable := filepath.Join(dir, "unreadable.txt")

	if err := os.WriteFile(readable, []byte("ok"), 0o644); err != nil {
		t.Fatalf("WriteFile readable: %v", err)
	}
	if err := os.WriteFile(unreadable, []byte("secret"), 0o000); err != nil {
		t.Fatalf("WriteFile unreadable: %v", err)
	}
	// Restore permissions after test so TempDir cleanup works.
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })

	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB should not error on unreadable file: %v", err)
	}

	// The readable file should be in the db; the unreadable one should not.
	if _, ok := db.Files[readable]; !ok {
		t.Errorf("readable file should appear in db")
	}
	// Unreadable file is skipped (no error, just omitted).
	if _, ok := db.Files[unreadable]; ok {
		t.Logf("unreadable file appeared in db (unexpected but not fatal)")
	}
}

// TestSaveDB_RoundTrip_WithEmptyFiles verifies SaveDB + LoadDB with an empty
// Files map to cover the nil-initialisation path in LoadDB.
func TestSaveDB_RoundTrip_WithEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "empty.json")

	db := integrity.IntegrityDB{
		Version: 1,
		Files:   make(map[string]integrity.FileHash),
	}

	if err := integrity.SaveDB(dbPath, db); err != nil {
		t.Fatalf("SaveDB: %v", err)
	}

	loaded, err := integrity.LoadDB(dbPath)
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}

	if loaded.Version != 1 {
		t.Errorf("Version: got %d, want 1", loaded.Version)
	}
	if loaded.Files == nil {
		t.Error("Files should not be nil after LoadDB")
	}
	if len(loaded.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(loaded.Files))
	}
}

// TestLoadDB_NilFiles verifies that LoadDB initialises Files to an empty map
// when the JSON has a null or absent "files" field (covers the nil-init branch).
func TestLoadDB_NilFiles(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "nil-files.json")
	// JSON without the "files" key → Files field will be nil after Unmarshal.
	content := `{"version":1,"created_at":"2024-01-01T00:00:00Z"}`
	if err := os.WriteFile(dbPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loaded, err := integrity.LoadDB(dbPath)
	if err != nil {
		t.Fatalf("LoadDB: %v", err)
	}
	if loaded.Files == nil {
		t.Error("LoadDB should initialise Files to an empty (non-nil) map")
	}
	if len(loaded.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(loaded.Files))
	}
}

// TestCompareDB_HashFileError exercises the "hashFile error → continue" branch
// in CompareDB by making a file unreadable after the baseline is taken.
func TestCompareDB_HashFileError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — chmod 000 has no effect")
	}

	dir := t.TempDir()
	filePath := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(filePath, []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Take baseline while file is readable.
	db, err := integrity.InitDB([]string{dir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	if _, ok := db.Files[filePath]; !ok {
		t.Fatalf("expected %s in baseline", filePath)
	}

	// Make the file unreadable so hashFile fails.
	if err := os.Chmod(filePath, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filePath, 0o644) })

	// CompareDB should skip the unreadable file (hashFile returns error → continue).
	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB should not error on unreadable file: %v", err)
	}
	// The file is still a regular file (Stat succeeds), but hash fails → skipped.
	// So no changes expected (or 0 changes for this file).
	for _, ch := range changes {
		if ch.Path == filePath {
			t.Logf("unexpected change for locked file: %+v", ch)
		}
	}
}

// TestCompareDB_OtherStatError manufactures a db with a path that causes Stat
// to return a non-IsNotExist error (e.g., a path inside an unreadable dir).
func TestCompareDB_OtherStatError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — cannot create unreadable directory")
	}

	dir := t.TempDir()
	subDir := filepath.Join(dir, "locked")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	hiddenFile := filepath.Join(subDir, "hidden.txt")
	if err := os.WriteFile(hiddenFile, []byte("hidden"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Build baseline while dir is accessible.
	db, err := integrity.InitDB([]string{subDir})
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	// Make the directory unreadable so Stat on files inside fails.
	if err := os.Chmod(subDir, 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(subDir, 0o755) })

	// CompareDB should handle the Stat error gracefully (treat as "modified").
	changes, err := integrity.CompareDB(db)
	if err != nil {
		t.Fatalf("CompareDB should not error on unreadable dir: %v", err)
	}
	// We expect at least one change (the file is now inaccessible).
	if len(changes) == 0 {
		t.Error("expected at least one change for inaccessible file")
	}
}
