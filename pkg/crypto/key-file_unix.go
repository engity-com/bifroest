//go:build unix && !linux

package crypto

import (
	"os"
	"path/filepath"
)

func installPrivateKeyFile(temporary, target string) error {
	if err := os.Link(temporary, target); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
