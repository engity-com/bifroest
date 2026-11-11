package session

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/uuidtext"
)

func validateFsStoredIdentity(ctx context.Context, id Id, metadataPath string, stored *Id) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if stored != nil {
		if *stored != id {
			return fmt.Errorf("stored session ID does not match selected binary UUID")
		}
		return nil
	}
	directory := filepath.Dir(metadataPath)
	name := filepath.Base(directory)
	// Case-folded hexadecimal UUID names cannot designate a different UUID.
	// Base58 names can. Missing-ID compatibility therefore requires the exact
	// actual directory entry, not FileInfo.Name (which may echo a lookup string).
	if name == uuidtext.Classic(id) {
		return nil
	}
	if name != id.String() {
		return fmt.Errorf("session directory does not match its selected UUID")
	}
	parent, err := os.Open(filepath.Dir(directory))
	if err != nil {
		return err
	}
	defer func() {
		if err := parent.Close(); resultErr == nil {
			resultErr = err
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, err := parent.Readdirnames(128)
		for _, entry := range names {
			if entry == name {
				return nil
			}
		}
		if err == io.EOF {
			return fmt.Errorf("legacy session metadata has no exact Base58 directory binding")
		}
		if err != nil {
			return err
		}
	}
}
