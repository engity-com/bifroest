package management

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func consoleInputPath(fd uintptr) (string, error) {
	var path [1024]byte
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, fd, unix.F_GETPATH, uintptr(unsafe.Pointer(&path[0]))); errno != 0 {
		return "", errno
	}
	return unix.ByteSliceToString(path[:]), nil
}

func readConsoleTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TIOCGETA)
}

func writeConsoleTermios(fd int, mode *unix.Termios, discard bool) error {
	command := uint(unix.TIOCSETA)
	if discard {
		command = unix.TIOCSETAF
	}
	return unix.IoctlSetTermios(fd, command, mode)
}
