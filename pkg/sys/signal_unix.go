//go:build unix

package sys

import (
	"os"
	"syscall"
)

const (
	SIGABRT   = Signal(syscall.SIGABRT)
	SIGALRM   = Signal(syscall.SIGALRM)
	SIGBUS    = Signal(syscall.SIGBUS)
	SIGCHLD   = Signal(syscall.SIGCHLD)
	SIGCLD    = Signal(syscall.SIGCLD)
	SIGCONT   = Signal(syscall.SIGCONT)
	SIGFPE    = Signal(syscall.SIGFPE)
	SIGHUP    = Signal(syscall.SIGHUP)
	SIGILL    = Signal(syscall.SIGILL)
	SIGINT    = Signal(syscall.SIGINT)
	SIGIO     = Signal(syscall.SIGIO)
	SIGIOT    = Signal(syscall.SIGIOT)
	SIGKILL   = Signal(syscall.SIGKILL)
	SIGPIPE   = Signal(syscall.SIGPIPE)
	SIGPOLL   = Signal(syscall.SIGPOLL)
	SIGPROF   = Signal(syscall.SIGPROF)
	SIGPWR    = Signal(syscall.SIGPWR)
	SIGQUIT   = Signal(syscall.SIGQUIT)
	SIGSEGV   = Signal(syscall.SIGSEGV)
	SIGSTOP   = Signal(syscall.SIGSTOP)
	SIGSYS    = Signal(syscall.SIGSYS)
	SIGTERM   = Signal(syscall.SIGTERM)
	SIGTRAP   = Signal(syscall.SIGTRAP)
	SIGTSTP   = Signal(syscall.SIGTSTP)
	SIGTTIN   = Signal(syscall.SIGTTIN)
	SIGTTOU   = Signal(syscall.SIGTTOU)
	SIGURG    = Signal(syscall.SIGURG)
	SIGUSR1   = Signal(syscall.SIGUSR1)
	SIGUSR2   = Signal(syscall.SIGUSR2)
	SIGVTALRM = Signal(syscall.SIGVTALRM)
	SIGWINCH  = Signal(syscall.SIGWINCH)
	SIGXCPU   = Signal(syscall.SIGXCPU)
	SIGXFSZ   = Signal(syscall.SIGXFSZ)
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
	return p.Signal(this.Native())
}
