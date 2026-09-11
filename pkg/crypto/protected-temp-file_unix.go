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
