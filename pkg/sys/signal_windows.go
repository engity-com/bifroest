//go:build windows

package sys

import (
	"syscall"
)

const (
	SIGABRT = Signal(syscall.SIGABRT)
	SIGALRM = Signal(syscall.SIGALRM)
	SIGBUS  = Signal(syscall.SIGBUS)
	SIGFPE  = Signal(syscall.SIGFPE)
	SIGHUP  = Signal(syscall.SIGHUP)
	SIGILL  = Signal(syscall.SIGILL)
	SIGINT  = Signal(syscall.SIGINT)
	SIGKILL = Signal(syscall.SIGKILL)
	SIGPIPE = Signal(syscall.SIGPIPE)
	SIGQUIT = Signal(syscall.SIGQUIT)
	SIGSEGV = Signal(syscall.SIGSEGV)
	SIGTERM = Signal(syscall.SIGTERM)
	SIGTRAP = Signal(syscall.SIGTRAP)
)

var (
	strToSignal = map[string]Signal{
		"ABRT": SIGABRT,
		"ALRM": SIGALRM,
		"BUS":  SIGBUS,
		"FPE":  SIGFPE,
		"HUP":  SIGHUP,
		"ILL":  SIGILL,
		"INT":  SIGINT,
		"KILL": SIGKILL,
		"PIPE": SIGPIPE,
		"QUIT": SIGQUIT,
		"SEGV": SIGSEGV,
		"TERM": SIGTERM,
		"TRAP": SIGTRAP,
	}
)
