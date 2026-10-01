//go:build darwin

package protocol

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

var (
	darwinSysctlOnce sync.Once
	darwinSysctl     uintptr
	darwinSysctlErr  error
)

func loadDarwinSysctl() error {
	darwinSysctlOnce.Do(func() {
		handle, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			darwinSysctlErr = err
			return
		}
		symbol, err := purego.Dlsym(handle, "sysctl")
		if err != nil || symbol == 0 {
			if err == nil {
				err = fmt.Errorf("symbol was not found")
			}
			darwinSysctlErr = err
			return
		}
		darwinSysctl = symbol
	})
	return darwinSysctlErr
}

func readDarwinProcessArguments(pid int) ([]byte, error) {
	maximum, err := unix.SysctlUint32("kern.argmax")
	if err != nil {
		return nil, err
	}
	if maximum == 0 {
		return nil, fmt.Errorf("kern.argmax returned zero")
	}
	if err := loadDarwinSysctl(); err != nil {
		return nil, fmt.Errorf("cannot load Darwin sysctl: %w", err)
	}
	buffer := make([]byte, int(maximum))
	size := uintptr(len(buffer))
	mib := [3]int32{1, 49, int32(pid)} // CTL_KERN, KERN_PROCARGS2, pid
	result, _, errno := purego.SyscallN(
		darwinSysctl,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)
	runtime.KeepAlive(mib)
	runtime.KeepAlive(buffer)
	if result != 0 {
		if errno != 0 {
			return nil, fmt.Errorf("kern.procargs2 failed for process %d: %w", pid, unix.Errno(errno))
		}
		return nil, fmt.Errorf("kern.procargs2 failed for process %d", pid)
	}
	if size > uintptr(len(buffer)) {
		return nil, fmt.Errorf("kern.procargs2 returned invalid size %d", size)
	}
	return buffer[:int(size)], nil
}
