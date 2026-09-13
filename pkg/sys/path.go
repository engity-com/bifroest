package sys

import (
	goerrors "errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// CanonicalPath returns an absolute path with symlinks in its longest existing
// prefix resolved. A missing path suffix is preserved without creating it.
func CanonicalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolute)
	var missing []string
	for {
		if _, err := os.Lstat(current); err == nil {
			canonical, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				canonical = filepath.Join(canonical, missing[index])
			}
			return filepath.Clean(canonical), nil
		} else if !goerrors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("cannot find existing parent of %q", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}
