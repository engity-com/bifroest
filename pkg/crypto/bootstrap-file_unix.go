//go:build unix && !linux

package crypto

import (
	"os"
	"path/filepath"
)

func installBootstrapFile(temporary, target string, force bool) error {
	var err error
	if force {
		err = os.Rename(temporary, target)
	} else if err = os.Link(temporary, target); err == nil {
		err = os.Remove(temporary)
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
