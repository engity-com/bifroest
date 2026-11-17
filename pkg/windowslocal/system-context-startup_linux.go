//go:build linux

package windowslocal

import (
	"os"
	"syscall"
)

func s4uOnStartupThread() (bool, error) { return syscall.Gettid() == os.Getpid(), nil }
