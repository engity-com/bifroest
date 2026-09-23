package audit

import (
	goerrors "errors"
	"os"
	"path/filepath"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const journalWorkDirectoryName = ".bifroest-work"

type journalSegmentWorkspace struct {
	path string
}

func newRecorderJournalSegmentWorkspace(journalDirectory string) (*journalSegmentWorkspace, error) {
	return newJournalSegmentWorkspaceInJournal(journalDirectory)
}

func newJournalSegmentWorkspaceInJournal(journalDirectory string) (*journalSegmentWorkspace, error) {
	root := filepath.Join(journalDirectory, journalWorkDirectoryName)
	if err := ensureJournalDirectory(root, true); err != nil {
		return nil, errors.System.Newf("cannot prepare private audit work directory %q: %w", root, err)
	}
	return newJournalSegmentWorkspace(root)
}

func newJournalSegmentWorkspace(parent string) (*journalSegmentWorkspace, error) {
	path, err := bfcrypto.CreateProtectedTempDirectory(parent, ".operation-*")
	if err != nil {
		return nil, errors.System.Newf("cannot create private audit segment workspace in %q: %w", parent, err)
	}
	return &journalSegmentWorkspace{path: path}, nil
}

func (this *journalSegmentWorkspace) Close() error {
	if this == nil || this.path == "" {
		return nil
	}
	path := this.path
	this.path = ""
	if err := os.Remove(path); err != nil && !goerrors.Is(err, os.ErrNotExist) {
		return errors.System.Newf("cannot remove private audit segment workspace %q: %w", path, err)
	}
	return nil
}
