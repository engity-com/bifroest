//go:build unix

package test

import "syscall"

// Opening an untrusted FIFO must not block before readSource can reject it.
const sourceOpenFlags = syscall.O_NONBLOCK
