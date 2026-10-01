//go:build unix

package sys

import (
	"fmt"
	"os"
	"syscall"
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
	native, ok := signalToNative(this)
	if !ok {
		return fmt.Errorf("unsupported signal on this operating system: %s", this)
	}
	return p.Signal(native)
}

func (this Signal) sendToPid(pid int) error {
	native, ok := signalToNative(this)
	if !ok {
		return fmt.Errorf("unsupported signal on this operating system: %s", this)
	}
	return syscall.Kill(pid, native)
}
