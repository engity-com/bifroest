//go:build unix

package sys

import (
	"os"
	"syscall"
)

const (
	// Signal values are part of the Bifroest protocol and stay compatible with Linux.
	SIGHUP    = Signal(1)
	SIGINT    = Signal(2)
	SIGQUIT   = Signal(3)
	SIGILL    = Signal(4)
	SIGTRAP   = Signal(5)
	SIGABRT   = Signal(6)
	SIGIOT    = SIGABRT
	SIGBUS    = Signal(7)
	SIGFPE    = Signal(8)
	SIGKILL   = Signal(9)
	SIGUSR1   = Signal(10)
	SIGSEGV   = Signal(11)
	SIGUSR2   = Signal(12)
	SIGPIPE   = Signal(13)
	SIGALRM   = Signal(14)
	SIGTERM   = Signal(15)
	SIGCHLD   = Signal(17)
	SIGCLD    = SIGCHLD
	SIGCONT   = Signal(18)
	SIGSTOP   = Signal(19)
	SIGTSTP   = Signal(20)
	SIGTTIN   = Signal(21)
	SIGTTOU   = Signal(22)
	SIGURG    = Signal(23)
	SIGXCPU   = Signal(24)
	SIGXFSZ   = Signal(25)
	SIGVTALRM = Signal(26)
	SIGPROF   = Signal(27)
	SIGWINCH  = Signal(28)
	SIGIO     = Signal(29)
	SIGPOLL   = SIGIO
	SIGPWR    = Signal(30)
	SIGSYS    = Signal(31)
)

var (
	strToSignal = map[string]Signal{
		"ABRT":   SIGABRT,
		"ALRM":   SIGALRM,
		"BUS":    SIGBUS,
		"CHLD":   SIGCHLD,
		"CLD":    SIGCLD,
		"CONT":   SIGCONT,
		"FPE":    SIGFPE,
		"HUP":    SIGHUP,
		"ILL":    SIGILL,
		"INT":    SIGINT,
		"IO":     SIGIO,
		"IOT":    SIGIOT,
		"KILL":   SIGKILL,
		"PIPE":   SIGPIPE,
		"POLL":   SIGPOLL,
		"PROF":   SIGPROF,
		"PWR":    SIGPWR,
		"QUIT":   SIGQUIT,
		"SEGV":   SIGSEGV,
		"STOP":   SIGSTOP,
		"SYS":    SIGSYS,
		"TERM":   SIGTERM,
		"TRAP":   SIGTRAP,
		"TSTP":   SIGTSTP,
		"TTIN":   SIGTTIN,
		"TTOU":   SIGTTOU,
		"URG":    SIGURG,
		"USR1":   SIGUSR1,
		"USR2":   SIGUSR2,
		"VTALRM": SIGVTALRM,
		"WINCH":  SIGWINCH,
		"XCPU":   SIGXCPU,
		"XFSZ":   SIGXFSZ,
	}
)

func (this Signal) sendToProcess(p *os.Process) error {
	native, err := this.Native()
	if err != nil {
		return err
	}
	return p.Signal(native)
}

func (this Signal) sendToPid(pid int) error {
	native, err := this.Native()
	if err != nil {
		return err
	}
	return syscall.Kill(pid, native)
}
