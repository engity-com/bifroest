package session

import (
	"fmt"
	"os"
	"path/filepath"
)

func writeFsFileAtomically(path string, data []byte, fileMode, dirMode os.FileMode) (rErr error) {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return fmt.Errorf("cannot create parent directory for %q: %w", path, err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary file for %q: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporary != nil {
			if err := temporary.Close(); err != nil && rErr == nil {
				rErr = err
			}
		}
		if rErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(fileMode); err != nil {
		return fmt.Errorf("cannot set mode of temporary file for %q: %w", path, err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("cannot write temporary file for %q: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("cannot flush temporary file for %q: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("cannot close temporary file for %q: %w", path, err)
	}
	temporary = nil
	if err := replaceFsFile(temporaryPath, path); err != nil {
		return fmt.Errorf("cannot atomically replace %q: %w", path, err)
	}
	if err := syncFsDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("cannot flush parent directory of %q: %w", path, err)
	}
	return nil
}
