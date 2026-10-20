package management

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func consoleInputPath(fd uintptr) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
}

func readConsoleTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TCGETS)
}

func writeConsoleTermios(fd int, mode *unix.Termios, discard bool) error {
	command := uint(unix.TCSETS)
	if discard {
		command = unix.TCSETSF
	}
	return unix.IoctlSetTermios(fd, command, mode)
}
