package management

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const disabledConsoleControl = 0

func consoleInputPath(fd uintptr) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
}

func readConsoleTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TCGETS)
}

func discardConsoleInput(fd int) error {
	// TCSETSF flushes N_TTY, but a completed PTY-master write can still be in
	// the earlier asynchronous flipbuffer. TCFLSH purges that buffer too before
	// the original mode can restore ECHO. TCIFLUSH is a scalar ioctl argument.
	return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
}

func writeConsoleTermios(fd int, mode *unix.Termios, discard bool) error {
	command := uint(unix.TCSETS)
	if discard {
		command = unix.TCSETSF
	}
	return unix.IoctlSetTermios(fd, command, mode)
}
