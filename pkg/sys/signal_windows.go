//go:build windows

package sys

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
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

	dllKernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole            = dllKernel32.NewProc("AttachConsole")
	procSetConsoleCtrlHandler    = dllKernel32.NewProc("SetConsoleCtrlHandler")
	procGenerateConsoleCtrlEvent = dllKernel32.NewProc("GenerateConsoleCtrlEvent")
)

func (this Signal) sendToPid(pid int) error {
	if this == SIGINT {
		return this.sendIntToPid(pid)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return this.sendToProcess(p)
}

func (this Signal) sendToProcess(p *os.Process) error {
	if this == SIGINT {
		return this.sendIntToPid(p.Pid)
	}
	return p.Signal(this.Native())
}

func (this Signal) sendIntToPid(pid int) error {
	r1, _, err := procAttachConsole.Call(uintptr(pid))
	if r1 == 0 && !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		return err
	}
	r1, _, err = procSetConsoleCtrlHandler.Call(0, 1)
	if r1 == 0 {
		return err
	}
	r1, _, err = procGenerateConsoleCtrlEvent.Call(windows.CTRL_BREAK_EVENT, uintptr(pid))
	if r1 == 0 {
		return err
	}
	return nil
}
