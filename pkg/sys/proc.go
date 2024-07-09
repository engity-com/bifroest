package sys

/*
__attribute__((noinline))
void* get_proc_self_address()
{
	return __builtin_extract_return_addr(__builtin_return_address(0));
}
*/
import "C"
import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
)

func GetProcSelfAddress() uintptr {
	return uintptr(C.get_proc_self_address())
}

func GetPathnameOfSelf() (string, error) {
	fail := func(err error) (string, error) {
		return "", err
	}
	failf := func(message string, args ...any) (string, error) {
		return fail(fmt.Errorf(message, args...))
	}

	addr := GetProcSelfAddress()
	if addr == 0 {
		return failf("cannot get the address of the current process via __builtin_extract_return_addr(__builtin_return_address(0)")
	}

	return GetPathnameOfAddr(addr)
}

func GetPathnameOfAddr(addr uintptr) (string, error) {
	// $ cat /proc/self/maps
	// 00400000-0040b000 r-xp 00000000 fc:01 787766                             /bin/cat
	// 0060a000-0060b000 r--p 0000a000 fc:01 787766                             /bin/cat
	// 0060b000-0060c000 rw-p 0000b000 fc:01 787766                             /bin/cat
	// 014ab000-014cc000 rw-p 00000000 00:00 0                                  [heap]
	// 7f7d76af8000-7f7d7797c000 r--p 00000000 fc:01 1318064                    /usr/lib/locale/locale-archive
	// 7f7d7797c000-7f7d77b36000 r-xp 00000000 fc:01 1180226                    /lib/x86_64-linux-gnu/libc-2.19.so
	// 7f7d77b36000-7f7d77d36000 ---p 001ba000 fc:01 1180226                    /lib/x86_64-linux-gnu/libc-2.19.so
	// 7f7d77d36000-7f7d77d3a000 r--p 001ba000 fc:01 1180226                    /lib/x86_64-linux-gnu/libc-2.19.so
	// 7f7d77d3a000-7f7d77d3c000 rw-p 001be000 fc:01 1180226                    /lib/x86_64-linux-gnu/libc-2.19.so
	// 7f7d77d3c000-7f7d77d41000 rw-p 00000000 00:00 0
	// 7f7d77d41000-7f7d77d64000 r-xp 00000000 fc:01 1180217                    /lib/x86_64-linux-gnu/ld-2.19.so
	// 7f7d77f3f000-7f7d77f42000 rw-p 00000000 00:00 0
	// 7f7d77f61000-7f7d77f63000 rw-p 00000000 00:00 0
	// 7f7d77f63000-7f7d77f64000 r--p 00022000 fc:01 1180217                    /lib/x86_64-linux-gnu/ld-2.19.so
	// 7f7d77f64000-7f7d77f65000 rw-p 00023000 fc:01 1180217                    /lib/x86_64-linux-gnu/ld-2.19.so
	// 7f7d77f65000-7f7d77f66000 rw-p 00000000 00:00 0
	// 7ffc342a2000-7ffc342c3000 rw-p 00000000 00:00 0                          [stack]
	// 7ffc34343000-7ffc34345000 r-xp 00000000 00:00 0                          [vdso]
	// ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

	fail := func(err error) (string, error) {
		return "", err
	}
	failf := func(message string, args ...any) (string, error) {
		return fail(fmt.Errorf(message, args...))
	}

	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return failf("cannot open /proc/self/maps: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		var start, end uintptr
		var path string
		offset := 0

		// address
		if start, offset = scanAddress(line, offset); offset < 0 {
			continue
		}
		if offset = expect(line, offset, '-'); offset < 0 {
			continue
		}
		if end, offset = scanAddress(line, offset); offset < 0 {
			continue
		}

		if offset = expectWhiteSpace(line, offset); offset < 0 {
			continue
		}

		// permission
		if offset = expectPermission(line, offset); offset < 0 {
			continue
		}

		if offset = expectWhiteSpace(line, offset); offset < 0 {
			continue
		}

		// offset
		if offset = expectAddress(line, offset); offset < 0 {
			continue
		}

		if offset = expectWhiteSpace(line, offset); offset < 0 {
			continue
		}

		// inode
		if offset = expectAddress(line, offset); offset < 0 {
			continue
		}
		if offset = expect(line, offset, ':'); offset < 0 {
			continue
		}
		if offset = expectAddress(line, offset); offset < 0 {
			continue
		}

		if offset = expectWhiteSpace(line, offset); offset < 0 {
			continue
		}

		// device
		if offset = expectInteger(line, offset); offset < 0 {
			continue
		}

		if offset = expectWhiteSpace(line, offset); offset < 0 {
			continue
		}

		if path, offset = scanString(line, offset); offset < 0 {
			continue
		}

		if start <= addr && addr <= end {
			return path, nil
		}
	}

	return "", nil
}

func scanAddress(from []byte, offset int) (uintptr, int) {
	if len(from) < offset {
		return 0, -1
	}
	for i, c := range from[offset:] {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			// acceptable
		} else if i > 0 {
			candidate := string(from[offset : offset+i])
			result, err := strconv.ParseUint(candidate, 16, 64)
			if err != nil {
				return 0, -1
			}
			return uintptr(result), offset + i
		} else {
			return 0, -1
		}
	}
	return 0, -1
}

func scanString(from []byte, offset int) (string, int) {
	lFrom := len(from)
	if lFrom < offset {
		return "", -1
	}
	return string(from[offset:]), lFrom
}

func expect(from []byte, offset int, what ...byte) int {
	lWhat := len(what)
	if len(from) < offset+lWhat {
		return -1
	}
	if bytes.Equal(from[offset:offset+lWhat], what) {
		return lWhat + offset
	}
	return -1
}

func expectWhiteSpace(from []byte, offset int) int {
	if len(from) < offset {
		return -1
	}
	for i, c := range from[offset:] {
		if c == ' ' || c == '\t' || c == '\r' {
			// acceptable
		} else {
			return offset + i
		}
	}
	return -1
}

func expectPermission(from []byte, offset int) int {
	if len(from) < offset+4 {
		return -1
	}
	if from[offset+0] != 'r' && from[offset+0] != '-' {
		return -1
	}
	if from[offset+1] != 'w' && from[offset+1] != '-' {
		return -1
	}
	if from[offset+2] != 'x' && from[offset+2] != '-' {
		return -1
	}
	if from[offset+3] != 'p' && from[offset+3] != '-' {
		return -1
	}
	return offset + 4
}

func expectAddress(from []byte, offset int) int {
	if len(from) < offset {
		return -1
	}
	for i, c := range from[offset:] {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			// acceptable
		} else if i > 0 {
			return offset + i
		} else {
			return -1
		}
	}
	return -1
}

func expectInteger(from []byte, offset int) int {
	if len(from) < offset {
		return -1
	}
	for i, c := range from[offset:] {
		if c >= '0' && c <= '9' {
			// acceptable
		} else if i > 0 {
			return offset + i
		} else {
			return -1
		}
	}
	return -1
}
