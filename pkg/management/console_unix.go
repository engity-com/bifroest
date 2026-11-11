//go:build linux || darwin

package management

import (
	"context"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type consoleInput struct {
	fd       int
	original *unix.Termios
	echo     bool
	output   io.Writer
}

func openConsoleInput(input uintptr, echo bool, output io.Writer) (*consoleInput, error) {
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
	// Canonical mode silently discards answers beyond the kernel's line limit.
	// Read and edit the line ourselves, keeping signal handling and a private fd.
	mode.Lflag |= unix.ISIG
	mode.Lflag &^= unix.ICANON | unix.ECHO | unix.ECHONL
	mode.Iflag |= unix.ICRNL
	mode.Cc[unix.VMIN], mode.Cc[unix.VTIME] = 1, 0
	if err := writeConsoleTermios(fd, &mode, false); err != nil {
		return fail(err)
	}
	return &consoleInput{fd: fd, original: original, echo: echo, output: output}, nil
}

func (this *consoleInput) close(discard bool) error {
	return closeConsoleInputLifecycle(discard,
		func() error { return discardConsoleInput(this.fd) },
		func() error { return writeConsoleTermios(this.fd, this.original, discard) },
		func() error { return unix.Close(this.fd) },
	)
}

func (this *consoleInput) readLine(ctx context.Context) (line []byte, resultErr error) {
	defer func() {
		if resultErr != nil {
			clear(line)
			line = nil
		}
	}()
	// Do not read past the newline: the next prompt reopens the terminal and
	// must still receive any already queued answer without a shared secret buffer.
	var buffer [1]byte
	defer clear(buffer[:])
	line = make([]byte, 0, maximumConsoleInputBytes)
	for {
		if err := ctx.Err(); err != nil {
			return line, err
		}
		n, err := unix.Read(this.fd, buffer[:])
		if errors.Is(err, unix.EAGAIN) {
			fds := []unix.PollFd{{Fd: int32(this.fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(fds, 50); err != nil && !errors.Is(err, unix.EINTR) {
				return line, err
			}
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return line, err
		}
		if n == 0 {
			return line, io.EOF
		}
		if err := ctx.Err(); err != nil {
			return line, err
		}
		value := buffer[0]
		switch {
		case value == '\n':
			if this.echo {
				err = writeConsoleText(this.output, "\n")
			}
			return line, err
		case this.control(value, unix.VEOF):
			return line, io.EOF
		case this.control(value, unix.VERASE):
			_, size := utf8.DecodeLastRune(line)
			line, err = this.erase(line, len(line)-size)
		case this.control(value, unix.VKILL):
			line, err = this.erase(line, 0)
		case this.original.Lflag&unix.IEXTEN != 0 && this.control(value, unix.VWERASE):
			start, word := len(line), false
			for start > 0 {
				last, size := utf8.DecodeLastRune(line[:start])
				if unicode.IsSpace(last) {
					if word {
						break
					}
				} else {
					word = true
				}
				start -= size
			}
			line, err = this.erase(line, start)
		default:
			if len(line) >= maximumConsoleInputBytes {
				return line, fmt.Errorf("SSH authentication input exceeds %d bytes", maximumConsoleInputBytes)
			}
			line = append(line, value)
			if this.echo {
				text := string(buffer[:n])
				if this.echoesControl(rune(value)) {
					text = "^" + string(rune(value^0x40))
				}
				err = writeConsoleText(this.output, text)
			}
		}
		clear(buffer[:])
		if err != nil {
			return line, err
		}
	}
}

func (this *consoleInput) control(value byte, index int) bool {
	configured := this.original.Cc[index]
	return configured != disabledConsoleControl && value == configured
}

func (this *consoleInput) echoesControl(value rune) bool {
	return this.original.Lflag&unix.ECHOCTL != 0 && (value < 0x20 && value != '\t' || value == 0x7f)
}

func (this *consoleInput) erase(line []byte, start int) ([]byte, error) {
	for len(line) > start {
		value, size := utf8.DecodeLastRune(line)
		clear(line[len(line)-size:])
		line = line[:len(line)-size]
		if this.echo {
			text := "\b \b"
			if this.echoesControl(value) {
				text += text
			}
			if err := writeConsoleText(this.output, text); err != nil {
				return line, err
			}
		}
	}
	return line, nil
}
