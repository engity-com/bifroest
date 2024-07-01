//go:build linux

package sys

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

var (
	ErrUnknownSignal = errors.New("unknown signal")
)

type Signal uint8

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
	SIGSTKFLT = Signal(syscall.SIGSTKFLT)
	SIGSTOP   = Signal(syscall.SIGSTOP)
	SIGSYS    = Signal(syscall.SIGSYS)
	SIGTERM   = Signal(syscall.SIGTERM)
	SIGTRAP   = Signal(syscall.SIGTRAP)
	SIGTSTP   = Signal(syscall.SIGTSTP)
	SIGTTIN   = Signal(syscall.SIGTTIN)
	SIGTTOU   = Signal(syscall.SIGTTOU)
	SIGUNUSED = Signal(syscall.SIGUNUSED)
	SIGURG    = Signal(syscall.SIGURG)
	SIGUSR1   = Signal(syscall.SIGUSR1)
	SIGUSR2   = Signal(syscall.SIGUSR2)
	SIGVTALRM = Signal(syscall.SIGVTALRM)
	SIGWINCH  = Signal(syscall.SIGWINCH)
	SIGXCPU   = Signal(syscall.SIGXCPU)
	SIGXFSZ   = Signal(syscall.SIGXFSZ)
)

func (this Signal) String() string {
	if this == 0 {
		return ""
	}

	str, ok := signalToStr[this]
	if !ok {
		return prefix0x + strconv.FormatUint(uint64(this), 16)
	}
	return prefixSig + str
}

func (this *Signal) Set(plain string) error {
	if len(plain) == 0 {
		*this = 0
		return nil
	}

	plainU := strings.ToUpper(plain)
	if strings.HasPrefix(plainU, prefixSig) {
		lookup := plainU[prefixSigLen:]
		candidate, ok := strToSignal[lookup]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownSignal, plain)
		}
		*this = candidate
		return nil
	}

	if strings.HasPrefix(plainU, prefix0X) {
		lookup := plainU[prefix0XLen:]
		candidate, err := strconv.ParseUint(lookup, 16, 8)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrUnknownSignal, plain)
		}
		*this = Signal(candidate)
		return nil
	}

	if candidate, ok := strToSignal[plainU]; ok {
		*this = Signal(candidate)
		return nil
	}

	if candidate, err := strconv.ParseUint(plainU, 10, 8); err == nil {
		*this = Signal(candidate)
		return nil
	}

	return fmt.Errorf("%w: %s", ErrUnknownSignal, plain)
}

func (this Signal) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *Signal) UnmarshalText(text []byte) error {
	return this.Set(string(text))
}

func (this Signal) IsZero() bool {
	return this == 0
}

func (this Signal) Native() syscall.Signal {
	return syscall.Signal(this)
}

func (this Signal) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case Signal:
		return this == v
	case *Signal:
		return this == *v
	case syscall.Signal:
		return this.Native() == v
	case *syscall.Signal:
		return this.Native() == *v
	default:
		return false
	}
}

const (
	prefixSig    = "SIG"
	prefixSigLen = len(prefixSig)

	prefix0x    = "0x"
	prefix0X    = "0X"
	prefix0XLen = len(prefix0X)
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
		"STKFLT": SIGSTKFLT,
		"STOP":   SIGSTOP,
		"SYS":    SIGSYS,
		"TERM":   SIGTERM,
		"TRAP":   SIGTRAP,
		"TSTP":   SIGTSTP,
		"TTIN":   SIGTTIN,
		"TTOU":   SIGTTOU,
		"UNUSED": SIGUNUSED,
		"URG":    SIGURG,
		"USR1":   SIGUSR1,
		"USR2":   SIGUSR2,
		"VTALRM": SIGVTALRM,
		"WINCH":  SIGWINCH,
		"XCPU":   SIGXCPU,
		"XFSZ":   SIGXFSZ,
	}

	signalToStr = func(in map[string]Signal) map[Signal]string {
		result := make(map[Signal]string, len(in))
		for str, sig := range in {
			result[sig] = str
		}
		return result
	}(strToSignal)
)
