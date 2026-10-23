package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/terminal"
)

type terminalUiCounters struct{ runs, resizes, interrupts atomic.Int32 }

// Test backend reached through the real shared execution/recording/lease driver,
// not a browser-side command emulator or a claim of real container execution.
func installTerminalUiBackend(svc *service) *terminalUiCounters {
	counters := &terminalUiCounters{}
	svc.environments.(*executionTestRepository).run = func(task environment.TerminalTask) (int, error) {
		stream := task.Terminal()
		run := counters.runs.Add(1)
		if _, err := io.WriteString(stream, "UTF8:"); err != nil {
			return -1, err
		}
		if _, err := stream.Write([]byte{0xe2}); err != nil {
			return -1, err
		}
		if _, err := stream.Write([]byte{0x82, 0xac, '\r', '\n'}); err != nil {
			return -1, err
		}
		_, _ = io.WriteString(stream.Stderr(), "STDERR_MARKER\r\n")
		_, _ = io.WriteString(stream, "\x1b]52;c;SGVsbG8=\x07\x1b]0;untrusted-backend-title\x07\x1b]8;;https://invalid.example/no-open\x07blocked-link\x1b]8;;\x07\r\n")
		_, _, hasPty := stream.Pty()
		_, _ = fmt.Fprintf(stream, "PTY:%t\r\nCOMMAND:%s\r\n", hasPty, stream.RawCommand())
		_, _ = fmt.Fprintf(stream, "EXECUTION_START:%d\r\n", run)
		_, windows, _ := stream.Pty()
		signals := make(chan terminal.Signal, 4)
		stream.Signals(signals)
		ctx, cancel := context.WithCancel(task.Context())
		var workers sync.WaitGroup
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case window, open := <-windows:
					if !open {
						windows = nil
						continue
					}
					counters.resizes.Add(1)
					_, _ = fmt.Fprintf(stream, "RESIZE:%dx%d\r\n", window.Width, window.Height)
				case signal := <-signals:
					if signal == "INT" {
						counters.interrupts.Add(1)
					}
					_, _ = fmt.Fprintf(stream, "SIGNAL:%s\r\n", signal)
				}
			}
		}()
		defer func() { cancel(); stream.Signals(nil); workers.Wait() }()
		reader := bufio.NewReader(stream)
		var line []byte
		for {
			value, err := reader.ReadByte()
			if err != nil {
				if task.Context().Err() != nil {
					return -1, task.Context().Err()
				}
				if err == io.EOF {
					_, _ = io.WriteString(stream, "OUTPUT_AFTER_EOF\r\n")
					return 7, nil
				}
				return -1, err
			}
			if value != '\r' && value != '\n' {
				line = append(line, value)
				if len(line) > 4096 {
					return -1, fmt.Errorf("test input bound exceeded")
				}
				continue
			}
			if string(line) == "drop" {
				_ = stream.Close()
				return -1, fmt.Errorf("test disconnect")
			}
			_, _ = fmt.Fprintf(stream, "STDIN:%s\r\n", line)
			line = line[:0]
		}
	}
	return counters
}
