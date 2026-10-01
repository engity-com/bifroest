//go:build unix && !darwin

package environment

import (
	"os"
	"syscall"
)

func configureLocalPtyDescriptors(pty, tty *os.File) error {
	if err := syscall.SetNonblock(int(pty.Fd()), true); err != nil {
		return err
	}
	return syscall.SetNonblock(int(tty.Fd()), true)
}
