//go:build unix

package audit

import (
	"encoding/binary"
	"os"
	"syscall"

	"github.com/engity-com/bifroest/pkg/errors"
)

func verifierFileIdentity(path string, _ *os.File, info os.FileInfo) ([16]byte, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return [16]byte{}, errors.System.Newf("cannot determine filesystem identity of %q", path)
	}
	var result [16]byte
	binary.BigEndian.PutUint64(result[:8], uint64(stat.Dev))
	binary.BigEndian.PutUint64(result[8:], uint64(stat.Ino))
	return result, nil
}
