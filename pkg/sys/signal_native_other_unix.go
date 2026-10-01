//go:build unix && !linux && !darwin

package sys

import "syscall"

func signalToNative(signal Signal) (syscall.Signal, bool) {
	return syscall.Signal(signal), true
}
