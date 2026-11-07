//go:build e2e

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"time"

	creackpty "github.com/creack/pty"
)

// Direct PTY proof inside the owned image, before any Bifroest process starts.
// The original binary is a mandatory negative control, not a skipped failure.
func shellCursorRegression() error {
	for _, original := range []string{"/bin/busybox", "/usr/local/libexec/e2e-original/busybox"} {
		if err := shellCursorCase(original, "1;5", false); err != nil {
			return err
		}
	}
	for _, position := range []string{"1;3", "1;5", "1;10", "2;5", "32767;32767"} {
		for _, fragmented := range []bool{false, true} {
			if err := shellCursorCase("", position, fragmented); err != nil {
				return err
			}
		}
	}
	fmt.Println("cursor regression: original prefix-loss reproduced; corrected shell preserves immediate command, UTF-8 and Ctrl/Alt arrows (10 cases)")
	return nil
}

type cursorOutput struct {
	sync.Mutex
	buffer                bytes.Buffer
	query, denied         chan struct{}
	queryOnce, deniedOnce sync.Once
}

func (o *cursorOutput) Write(p []byte) (int, error) {
	o.Lock()
	defer o.Unlock()
	if o.buffer.Len()+len(p) > 64<<10 {
		return 0, errors.New("cursor proof exceeded output bound")
	}
	n, err := o.buffer.Write(p)
	if bytes.Contains(o.buffer.Bytes(), []byte("\x1b[6n")) {
		o.queryOnce.Do(func() { close(o.query) })
	}
	if bytes.Contains(o.buffer.Bytes(), []byte("sh: not found")) {
		o.deniedOnce.Do(func() { close(o.denied) })
	}
	return n, err
}

func shellCursorCase(original string, position string, fragmented bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-i")
	if original != "" {
		command = exec.CommandContext(ctx, original, "ash", "-i")
	}
	// This is also the real Docker fixture's deliberately restrictive PATH.
	// Dropping "exec /bin/" must not accidentally pass by finding another sh.
	command.Env = []string{"TERM=xterm-256color", "PS1=~ $ ", "PATH=/usr/local/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/home/e2e"}
	terminal, err := creackpty.StartWithSize(command, &creackpty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		return err
	}
	output := &cursorOutput{query: make(chan struct{}), denied: make(chan struct{})}
	read := make(chan struct{})
	go func() { _, _ = io.Copy(output, terminal); close(read) }()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	defer func() {
		cancel()
		_ = terminal.Close()
		<-read
	}()
	failure := func(reason string) error {
		output.Lock()
		defer output.Unlock()
		return fmt.Errorf("cursor case original=%q position=%s fragmented=%t: %s; output=%q", original, position, fragmented, reason, output.buffer.String())
	}
	select {
	case <-output.query:
	case <-ctx.Done():
		return failure("no actual shell cursor query")
	}
	// One response immediately followed by real input. No response suppression,
	// retry, pacing, sleep or dependence on when the shell schedules its read.
	payload := []byte("\x1b[" + position + "Rexec /bin/sh -c 'printf \"\\nCURSOR_EXECUTED:€\\n\"; exit 23'")
	// Existing Ctrl/Alt word-motion sequences must remain keys, not cursor reports.
	payload = append(payload, []byte("\x1b[1;5D\x1b[1;5C\x1b[1;3D\x1b[1;3C\r")...)
	for offset := 0; offset < len(payload); {
		end := len(payload)
		if fragmented {
			end = offset + 1
		}
		n, err := terminal.Write(payload[offset:end])
		if err != nil {
			return err
		}
		offset += n
	}
	if original != "" {
		select {
		case <-output.denied:
			cancel()
			<-wait
		case <-ctx.Done():
			return failure("negative control did not reproduce the original defect")
		}
	} else {
		select {
		case err := <-wait:
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 23 {
				return failure("outer shell exit=" + strconv.Itoa(exitCodeOf(err)))
			}
		case <-ctx.Done():
			return failure("corrected shell did not exec/exit")
		}
	}
	<-read
	_ = terminal.Close()
	output.Lock()
	text := output.buffer.String()
	output.Unlock()
	if bytes.Contains([]byte(text), []byte("\r\nCURSOR_EXECUTED:€\r\n")) == (original != "") {
		return failure("unexpected executed marker")
	}
	return nil
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		return exited.ExitCode()
	}
	return -1
}
