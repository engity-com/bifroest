//go:build linux

package sys

import "syscall"

func signalToNative(signal Signal) (syscall.Signal, bool) {
	return syscall.Signal(signal), true
}
