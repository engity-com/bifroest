//go:build darwin && cgo

package protocol

/*
#include <sys/types.h>
#include <sys/sysctl.h>

static int bifroest_procargs2(int pid, void *buffer, size_t *size) {
	int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
	return sysctl(mib, 3, buffer, size, NULL, 0);
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func readDarwinProcessArguments(pid int) ([]byte, error) {
	maximum, err := unix.SysctlUint32("kern.argmax")
	if err != nil {
		return nil, err
	}
	if maximum == 0 {
		return nil, fmt.Errorf("kern.argmax returned zero")
	}
	buffer := make([]byte, int(maximum))
	size := C.size_t(len(buffer))
	result, callErr := C.bifroest_procargs2(C.int(pid), unsafe.Pointer(&buffer[0]), &size)
	if result != 0 {
		return nil, callErr
	}
	if uint64(size) > uint64(len(buffer)) {
		return nil, fmt.Errorf("kern.procargs2 returned invalid size %d", uint64(size))
	}
	return buffer[:int(size)], nil
}
