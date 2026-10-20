//go:build linux || darwin

package management

import (
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

type consoleInput struct {
	fd       int
	original *unix.Termios
}

func openConsoleInput(input uintptr, echo bool, _ io.Writer) (*consoleInput, error) {
	path, err := consoleInputPath(input)
	if err != nil {
		return nil, fmt.Errorf("cannot locate SSH authentication terminal: %w", err)
	}
	// A fresh open file description keeps O_NONBLOCK off the caller's stdin.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open SSH authentication terminal: %w", err)
	}
	fail := func(err error) (*consoleInput, error) {
		_ = unix.Close(fd)
		return nil, err
	}
	var source, opened unix.Stat_t
	if err := unix.Fstat(int(input), &source); err != nil {
		return fail(err)
	}
	if err := unix.Fstat(fd, &opened); err != nil {
		return fail(err)
	}
	if source.Dev != opened.Dev || source.Ino != opened.Ino {
		return fail(fmt.Errorf("SSH authentication terminal changed while opening"))
	}
	original, err := readConsoleTermios(fd)
	if err != nil {
		return fail(err)
	}
	mode := *original
	mode.Lflag |= unix.ICANON | unix.ISIG
	mode.Iflag |= unix.ICRNL
	mode.Lflag &^= unix.ECHO | unix.ECHONL
	if echo {
		mode.Lflag |= unix.ECHO
	}
	if err := writeConsoleTermios(fd, &mode, false); err != nil {
		return fail(err)
	}
	return &consoleInput{fd: fd, original: original}, nil
}

func (this *consoleInput) close(discard bool) error {
	return errors.Join(writeConsoleTermios(this.fd, this.original, discard), unix.Close(this.fd))
}

func (this *consoleInput) readLine(ctx context.Context) (line []byte, resultErr error) {
	defer func() {
		if resultErr != nil {
			clear(line)
			line = nil
		}
	}()
	var buffer [256]byte
	defer clear(buffer[:])
	line = make([]byte, 0, maximumConsoleInputBytes)
	for {
		if err := ctx.Err(); err != nil {
			return line, err
		}
		fds := []unix.PollFd{{Fd: int32(this.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return line, err
		}
		if err := ctx.Err(); err != nil {
			return line, err
		}
		if fds[0].Revents == 0 {
			continue
		}
		n, err := unix.Read(this.fd, buffer[:])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return line, err
		}
		if n == 0 {
			return line, io.EOF
		}
		for _, value := range buffer[:n] {
			if value == '\n' {
				clear(buffer[:])
				return line, nil
			}
			if len(line) >= maximumConsoleInputBytes {
				clear(buffer[:])
				return line, fmt.Errorf("SSH authentication input exceeds %d bytes", maximumConsoleInputBytes)
			}
			line = append(line, value)
		}
		clear(buffer[:])
	}
}
