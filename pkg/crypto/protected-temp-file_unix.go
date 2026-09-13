//go:build unix

package crypto

import (
	"os"
)

func createProtectedTempFile(parent, pattern string, mode os.FileMode) (*os.File, error) {
	file, err := os.CreateTemp(parent, pattern)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, err
	}
	return file, nil
}

func createProtectedTempDirectory(parent, pattern string) (string, error) {
	path, err := os.MkdirTemp(parent, pattern)
	if err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0700); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}
