package session

import (
	"bytes"
	"context"
	"fmt"
	"os"
)

func (this *fs) UpdateEnvironmentTokenForCleanup(ctx context.Context, expected, updated []byte) error {
	if len(expected) == 0 || len(updated) == 0 {
		return fmt.Errorf("cleanup may only update an existing nonempty environment token")
	}
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()
	if _, err := this.repository.findBy(ctx, this.flow, this.id, nil, false); err != nil {
		return fmt.Errorf("cannot verify session before updating cleanup token: %w", err)
	}
	path, err := this.repository.file(this.flow, this.id, FsFileEnvironmentToken)
	if err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("environment token changed during account cleanup")
	}
	if err := writeFsFileAtomically(path, updated, os.FileMode(this.repository.conf.FileMode), os.FileMode(this.repository.dirFileMode())); err != nil {
		return fmt.Errorf("cannot persist cleanup progress: %w", err)
	}
	return nil
}
