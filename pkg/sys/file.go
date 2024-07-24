package sys

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
)

func TempFileNameFor(basename string) string {
	return filepath.Join(filepath.Dir(basename), filepath.Base(basename)+"~"+strconv.FormatUint(rand.Uint64(), 10))
}

func SafeSwapFiles(a, b string) error {
	var try uint16
	var aTmp string
	for {
		aTmp = TempFileNameFor(a)
		err := os.Rename(a, aTmp)
		if os.IsExist(err) {
			if try++; try < 10000 {
				continue
			}
			return fmt.Errorf("cannot rename %q to %q: %w", a, aTmp, err)
		}
		if err != nil {
			return err
		}
		break
	}

	if err := os.Rename(b, a); err != nil {
		return fmt.Errorf("cannot rename %q to %q: %w", b, a, err)
	}

	if err := os.Rename(aTmp, b); err != nil {
		return fmt.Errorf("cannot rename %q to %q: %w", aTmp, b, err)
	}

	return nil
}
