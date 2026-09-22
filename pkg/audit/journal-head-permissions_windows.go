//go:build windows

package audit

import (
	"os"

	"github.com/engity-com/bifroest/pkg/errors"
)

func protectJournalHead(path string, file *os.File) error {
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot flush audit journal head %q: %w", path, err)
	}
	return nil
}

func openJournalHead(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.System.Newf("cannot open audit journal head %q: %w", path, err)
	}
	return file, nil
}
