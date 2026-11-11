// Package uuidpath resolves old UUID filenames without renaming stored data.
package uuidpath

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/engity-com/bifroest/pkg/uuidtext"
)

// Resolve returns the sole existing notation, or the new Base58 path when
// neither exists. Two aliases fail closed, even when they are hardlinks: callers
// must never silently choose one identity's storage or delete its other alias.
func Resolve(directory string, id [16]byte, suffix string) (string, error) {
	path, _, err := ResolveExisting(directory, id, suffix)
	return path, err
}

func ResolveExisting(directory string, id [16]byte, suffix string) (string, bool, error) {
	currentName := uuidtext.Format(id) + suffix
	legacyName := uuidtext.Classic(id) + suffix
	// Check both completed names before probing either alias. A UUID rendering
	// does not make an arbitrary suffix safe, and both paths must remain local.
	if !filepath.IsLocal(currentName) || !filepath.IsLocal(legacyName) ||
		strings.ContainsAny(currentName+legacyName, "/\\:\x00") ||
		strings.TrimRight(currentName, ". ") != currentName || strings.TrimRight(legacyName, ". ") != legacyName {
		return "", false, fmt.Errorf("UUID storage name must be a single local file component")
	}
	current := filepath.Join(directory, currentName)
	legacy := filepath.Join(directory, legacyName)
	a, err := exists(current)
	if err != nil {
		return "", false, err
	}
	b, err := exists(legacy)
	if err != nil {
		return "", false, err
	}
	if a && b {
		return "", false, fmt.Errorf("ambiguous UUID storage aliases for %s", uuidtext.Format(id))
	}
	if b {
		return legacy, true, nil
	}
	return current, a, nil
}
func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func Canonical(text string, id [16]byte) bool {
	return text == uuidtext.Format(id) || text == uuidtext.Classic(id)
}

// CheckAliases is a bounded metadata-only preflight. It must precede recovery
// or cleanup, so ambiguity cannot cause an arbitrary alias to be modified.
func CheckAliases(ctx context.Context, directory, suffix string) error {
	f, err := os.Open(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		entries, readErr := f.ReadDir(128)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if suffix != "" && !strings.HasSuffix(name, suffix) {
				continue
			}
			text := strings.TrimSuffix(name, suffix)
			id, err := uuidtext.Parse(text)
			if err != nil {
				continue
			}
			if !Canonical(text, id) {
				return fmt.Errorf("unsupported UUID storage alias %q", name)
			}
			if _, err := Resolve(directory, id, suffix); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return ctx.Err()
		}
		if readErr != nil {
			return readErr
		}
	}
}
