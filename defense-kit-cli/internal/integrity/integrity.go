// Package integrity provides hash-based file integrity monitoring for critical
// system paths.  It can create a baseline database, persist it to JSON, reload
// it, and compare the current state of the filesystem against the baseline.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// FileHash holds all integrity metadata for a single file.
type FileHash struct {
	Path    string      `json:"path"`
	SHA256  string      `json:"sha256"`
	Size    int64       `json:"size"`
	Mode    os.FileMode `json:"mode"`
	ModTime time.Time   `json:"mod_time"`
}

// IntegrityDB is the complete baseline snapshot.
type IntegrityDB struct {
	Version   int                 `json:"version"`
	CreatedAt time.Time           `json:"created_at"`
	Files     map[string]FileHash `json:"files"` // key: absolute path
}

// IntegrityChange describes a single difference detected between the saved
// baseline and the current filesystem state.
type IntegrityChange struct {
	Path    string `json:"path"`
	// Type is one of "modified", "added", or "removed".
	Type    string `json:"type"`
	OldHash string `json:"old_hash,omitempty"`
	NewHash string `json:"new_hash,omitempty"`
}

// DefaultPaths returns the set of critical system directories and files that
// should be monitored by default.
func DefaultPaths() []string {
	return []string{
		"/usr/bin",
		"/usr/sbin",
		"/bin",
		"/sbin",
		"/etc/ssh/",
		"/etc/pam.d/",
		"/etc/cron.d/",
		"/etc/sudoers",
	}
}

// InitDB walks each path in paths, computes the SHA-256 hash of every regular
// file found, and returns a populated IntegrityDB.
func InitDB(paths []string) (IntegrityDB, error) {
	db := IntegrityDB{
		Version:   1,
		CreatedAt: time.Now(),
		Files:     make(map[string]FileHash),
	}

	for _, p := range paths {
		if err := walkPath(p, db.Files); err != nil {
			// Non-fatal: log and continue so a missing /etc/cron.d doesn't
			// abort the entire baseline.
			continue
		}
	}
	return db, nil
}

// walkPath recurses into p (or hashes p if it is a regular file) and stores
// results in dest.
func walkPath(p string, dest map[string]FileHash) error {
	return filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip unreadable entries (e.g., permission denied) without aborting.
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			// Skip symlinks, devices, pipes, etc.
			return nil
		}

		hash, err := hashFile(path)
		if err != nil {
			// Skip files we can't read.
			return nil
		}

		dest[path] = FileHash{
			Path:    path,
			SHA256:  hash,
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
		}
		return nil
	})
}

// hashFile computes the SHA-256 digest of the named file and returns it as a
// lowercase hex string.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CompareDB re-hashes every file in the saved database and reports files that
// have been modified, added to monitored paths (only for paths already in the
// DB), or removed.
//
// NOTE: "added" detection only works for new files inside directories that
// already have at least one entry in the database.  Full directory rescanning
// is not performed to keep the function read-only and focused.
func CompareDB(db IntegrityDB) ([]IntegrityChange, error) {
	var changes []IntegrityChange

	// Check every path stored in the baseline.
	for path, saved := range db.Files {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				changes = append(changes, IntegrityChange{
					Path:    path,
					Type:    "removed",
					OldHash: saved.SHA256,
				})
				continue
			}
			// Other stat errors — treat as modified/unknown.
			changes = append(changes, IntegrityChange{
				Path:    path,
				Type:    "modified",
				OldHash: saved.SHA256,
			})
			continue
		}

		if !info.Mode().IsRegular() {
			// Type changed (e.g., replaced by symlink).
			changes = append(changes, IntegrityChange{
				Path:    path,
				Type:    "modified",
				OldHash: saved.SHA256,
			})
			continue
		}

		currentHash, err := hashFile(path)
		if err != nil {
			continue
		}
		if currentHash != saved.SHA256 {
			changes = append(changes, IntegrityChange{
				Path:    path,
				Type:    "modified",
				OldHash: saved.SHA256,
				NewHash: currentHash,
			})
		}
	}

	return changes, nil
}

// SaveDB serialises db to a JSON file at path.  The file is written atomically
// via a temporary file to avoid partial writes.
func SaveDB(path string, db IntegrityDB) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal integrity db: %w", err)
	}

	// Write to a temporary file in the same directory, then rename.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".integrity-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// LoadDB reads and deserialises a JSON integrity database from path.
func LoadDB(path string) (IntegrityDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return IntegrityDB{}, fmt.Errorf("read integrity db: %w", err)
	}
	var db IntegrityDB
	if err := json.Unmarshal(data, &db); err != nil {
		return IntegrityDB{}, fmt.Errorf("unmarshal integrity db: %w", err)
	}
	if db.Files == nil {
		db.Files = make(map[string]FileHash)
	}
	return db, nil
}
