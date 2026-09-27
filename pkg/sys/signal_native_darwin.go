//go:build darwin

package sys

import "syscall"

var signalToNativeDarwin = map[Signal]syscall.Signal{
	0:         0,
	SIGHUP:    syscall.SIGHUP,
	SIGINT:    syscall.SIGINT,
	SIGQUIT:   syscall.SIGQUIT,
	SIGILL:    syscall.SIGILL,
	SIGTRAP:   syscall.SIGTRAP,
	SIGABRT:   syscall.SIGABRT,
	SIGBUS:    syscall.SIGBUS,
	SIGFPE:    syscall.SIGFPE,
	SIGKILL:   syscall.SIGKILL,
	SIGUSR1:   syscall.SIGUSR1,
	SIGSEGV:   syscall.SIGSEGV,
	SIGUSR2:   syscall.SIGUSR2,
	SIGPIPE:   syscall.SIGPIPE,
	SIGALRM:   syscall.SIGALRM,
	SIGTERM:   syscall.SIGTERM,
	SIGCHLD:   syscall.SIGCHLD,
	SIGCONT:   syscall.SIGCONT,
	SIGSTOP:   syscall.SIGSTOP,
	SIGTSTP:   syscall.SIGTSTP,
	SIGTTIN:   syscall.SIGTTIN,
	SIGTTOU:   syscall.SIGTTOU,
	SIGURG:    syscall.SIGURG,
	SIGXCPU:   syscall.SIGXCPU,
	SIGXFSZ:   syscall.SIGXFSZ,
	SIGVTALRM: syscall.SIGVTALRM,
	SIGPROF:   syscall.SIGPROF,
	SIGWINCH:  syscall.SIGWINCH,
	SIGIO:     syscall.SIGIO,
	SIGSYS:    syscall.SIGSYS,
}

var signalFromNativeDarwin = func() map[syscall.Signal]Signal {
	result := make(map[syscall.Signal]Signal, len(signalToNativeDarwin))
	for protocol, native := range signalToNativeDarwin {
		result[native] = protocol
	}
	return result
}()

func signalToNative(signal Signal) (syscall.Signal, bool) {
	result, ok := signalToNativeDarwin[signal]
	return result, ok
}

func signalFromNative(signal syscall.Signal) (Signal, bool) {
	result, ok := signalFromNativeDarwin[signal]
	return result, ok
}
