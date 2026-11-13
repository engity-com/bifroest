package service

import (
	"errors"
	"io"
)

// Configured shell banners are text, unlike the backend's terminal stream. SSH
// already applies PTY line endings on channel writes; make generated banner text
// explicit before delivery/capture so browser terminals see the same columns.
// Never apply this reader to process output, exec/subsystem data or old recordings.
type bannerTextReader struct {
	source         io.Reader
	buffer         [4096]byte
	start, end     int
	readErr        error
	carriageReturn bool
}

func (r *bannerTextReader) Read(output []byte) (int, error) {
	if len(output) == 0 {
		return 0, nil
	}
	if r.start == r.end {
		if r.readErr != nil {
			return 0, r.readErr
		}
		n, err := r.source.Read(r.buffer[:])
		if n < 0 || n > len(r.buffer) {
			return 0, errors.New("banner reader returned an invalid byte count")
		}
		r.start, r.end, r.readErr = 0, n, err
		if n == 0 {
			return 0, err
		}
	}
	written := 0
	for written < len(output) && r.start < r.end {
		value := r.buffer[r.start]
		if value == '\n' && !r.carriageReturn {
			output[written] = '\r'
			r.carriageReturn = true
			// Leave LF pending if the caller's buffer has room for only CR.
		} else {
			output[written] = value
			r.start++
			r.carriageReturn = value == '\r'
		}
		written++
	}
	return written, nil
}

func copyShellBanner(target io.Writer, source io.Reader, pty bool) (int64, error) {
	if pty {
		source = &bannerTextReader{source: source}
	}
	return io.Copy(target, source)
}
