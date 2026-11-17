//go:build windows

package environment

import (
	"errors"
	"io"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// The owning File is closed only after this synchronous read loop has joined.
// Unlike regular files, a successful zero-byte pipe read is an empty message,
// not EOF. Only a broken pipe confirms that its writer has finished.
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-readfile#pipes
type localConPTYOutputReader struct {
	handle       windows.Handle
	observation  *localConPTYRelayObservation
	rootProcess  atomic.Uintptr
	closeStarted atomic.Bool
}

func (r *localConPTYOutputReader) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	var count uint32
	err := windows.ReadFile(r.handle, data, &count, nil)
	if count == 0 && err == nil && r.observation != nil {
		r.observation.emptyReads++
	}
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) && r.observation != nil {
		r.observation.eofBeforeClose = !r.closeStarted.Load()
		if root := r.rootProcess.Load(); root != 0 {
			r.observation.rootAtNativeEOF = observeLocalConPTYRootState(func() (uint32, error) {
				return windows.WaitForSingleObject(windows.Handle(root), 0)
			})
		}
	}
	return localConPTYOutputReadResult(count, err)
}

func localConPTYOutputReadResult(count uint32, err error) (int, error) {
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) {
		return int(count), io.EOF
	}
	return int(count), err
}
