package crypto

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// EnsurePrivateDirectory opens or creates a service-owned private directory.
// Existing permissions/ACLs are validated, never silently repaired. The caller
// owns the returned handle and can use SameFile to detect path replacement.
func EnsurePrivateDirectory(path string) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("private directory path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err := createPrivateDirectory(path); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("private directory is not a real directory")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && !os.SameFile(before, info) {
		err = fmt.Errorf("private directory changed while opening")
	}
	if err == nil {
		err = validatePrivateDirectory(path, file, info)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
