package nanoserver

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

// Only for owned, offline fixture copies: Docker cp does not transfer the source
// system's private permissions. Preserve bytes, including invalid metadata.
func protectCopiedSessionOwnership(storage string) error {
	return filepath.WalkDir(storage, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected symlink in copied session evidence")
		}
		if entry.IsDir() || entry.Name() != session.FsFileRuntimeOwnership && entry.Name() != session.FsFileRuntimeRevocation {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return crypto.WriteBootstrapFile(path, raw, true)
	})
}
