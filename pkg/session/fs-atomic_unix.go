//go:build unix

package session

import (
	"os"
)

func replaceFsFile(from, to string) error { return os.Rename(from, to) }

func syncFsDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
