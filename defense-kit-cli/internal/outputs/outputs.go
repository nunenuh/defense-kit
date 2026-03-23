// Package outputs manages scan output directories under ~/.defense-kit/outputs/.
package outputs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Entry describes a single scan output directory.
type Entry struct {
	Name    string
	Path    string
	ModTime time.Time
	Size    int64 // total bytes in the directory
}

// List returns all scan output entries in dir, sorted oldest-first (by
// directory name, which is timestamp-based).
func List(dir string) ([]Entry, error) {
	infos, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("outputs: read dir %q: %w", dir, err)
	}

	var entries []Entry
	for _, info := range infos {
		if !info.IsDir() {
			continue
		}
		full := filepath.Join(dir, info.Name())
		fi, statErr := info.Info()
		if statErr != nil {
			continue
		}
		size := dirSize(full)
		entries = append(entries, Entry{
			Name:    info.Name(),
			Path:    full,
			ModTime: fi.ModTime(),
			Size:    size,
		})
	}

	// Sort by name (which encodes the timestamp) ascending.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	return entries, nil
}

// Clean removes all but the newest keep entries in dir.
// If keep <= 0 all entries are deleted.
// Returns the number of entries deleted.
func Clean(dir string, keep int) (int, error) {
	entries, err := List(dir)
	if err != nil {
		return 0, err
	}

	if keep < 0 {
		keep = 0
	}

	deleteCount := len(entries) - keep
	if deleteCount <= 0 {
		return 0, nil
	}

	toDelete := entries[:deleteCount]
	deleted := 0
	for _, e := range toDelete {
		if removeErr := os.RemoveAll(e.Path); removeErr != nil {
			return deleted, fmt.Errorf("outputs: remove %q: %w", e.Path, removeErr)
		}
		deleted++
	}
	return deleted, nil
}

// dirSize returns the total byte size of all regular files under root.
func dirSize(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}
