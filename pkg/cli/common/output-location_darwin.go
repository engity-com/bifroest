package common

import (
	"io/fs"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type outputMount struct {
	filesystem unix.Fsid
	point      string
	points     []string
}

func locateSingleLinkOutput(output *os.File, info fs.FileInfo) (string, outputMount, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return "", outputMount{}, false
	}
	// Darwin's F_GETPATH requires a PATH_MAX-sized buffer (1024 bytes).
	var buffer [1024]byte
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, output.Fd(), unix.F_GETPATH, uintptr(unsafe.Pointer(&buffer[0]))); errno != 0 {
		return "", outputMount{}, false
	}
	var mount unix.Statfs_t
	if err := unix.Fstatfs(int(output.Fd()), &mount); err != nil {
		return "", outputMount{}, false
	}
	count, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return "", outputMount{}, false
	}
	mounts := make([]unix.Statfs_t, count+8)
	count, err = unix.Getfsstat(mounts, unix.MNT_NOWAIT)
	if err != nil || count >= len(mounts) {
		return "", outputMount{}, false
	}
	points := make([]string, 0, count)
	for _, current := range mounts[:count] {
		points = append(points, unix.ByteSliceToString(current.Mntonname[:]))
	}
	return unix.ByteSliceToString(buffer[:]), outputMount{mount.Fsid, unix.ByteSliceToString(mount.Mntonname[:]), points}, true
}

func (this outputMount) matches(directory string) bool {
	var mount unix.Statfs_t
	if err := unix.Statfs(directory, &mount); err != nil {
		return false
	}
	return this.filesystem == mount.Fsid && this.point == unix.ByteSliceToString(mount.Mntonname[:]) && !hasMountBelow(directory, this.points)
}
