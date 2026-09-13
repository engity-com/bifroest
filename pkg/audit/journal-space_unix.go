//go:build unix

package audit

import (
	"fmt"
	"math"

	"golang.org/x/sys/unix"
)

func availableJournalBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize < 0 {
		return 0, fmt.Errorf("filesystem returned a negative block size")
	}
	blocks, blockSize := uint64(stat.Bavail), uint64(stat.Bsize)
	if blockSize > 0 && blocks > math.MaxUint64/blockSize {
		return math.MaxUint64, nil
	}
	return blocks * blockSize, nil
}
