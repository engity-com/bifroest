package environment

import (
	"os"
	"syscall"
	"unsafe"
)

func (this *Local) setWinsize(f *os.File, w, h int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
	if err == 0 {
		return nil
	}
	return err
}
