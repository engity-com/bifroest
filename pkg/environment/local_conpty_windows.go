//go:build windows

package environment

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	essh "github.com/engity-com/ssh-server-go"
)

type localConPTYFrame struct {
	kind byte
	data []byte
}

const localConPTYRelayExitPrefix = "\nBIFROEST-CONPTY/1 EXIT "

// WriteLocalConPTYRelayExitStatus confirms a shell exit only after the relay
// has successfully drained its output. Stderr is separate from PTY output.
func WriteLocalConPTYRelayExitStatus(out io.Writer, code int) error {
	if code < 0 || uint64(code) > uint64(^uint32(0)) {
		return fmt.Errorf("invalid ConPTY shell exit code %d", code)
	}
	status := fmt.Sprintf("%s%08x\n", localConPTYRelayExitPrefix, uint32(code))
	n, err := io.WriteString(out, status)
	if err != nil {
		return err
	}
	if n != len(status) {
		return io.ErrShortWrite
	}
	return nil
}

type localConPTYRelayStatusWriter struct {
	tail      [4096]byte
	length    int
	truncated bool
}

type localConPTYOutputWriter struct {
	io.Writer
	writingSince atomic.Pointer[time.Time]
}

func (this *localConPTYOutputWriter) Write(data []byte) (int, error) {
	started := time.Now()
	this.writingSince.Store(&started)
	defer this.writingSince.Store(nil)
	return this.Writer.Write(data)
}

func (this *localConPTYRelayStatusWriter) Write(data []byte) (int, error) {
	length := len(data)
	if length >= len(this.tail) {
		copy(this.tail[:], data[length-len(this.tail):])
		this.truncated = this.truncated || this.length > 0 || length > len(this.tail)
		this.length = len(this.tail)
		return length, nil
	}
	if discard := this.length + length - len(this.tail); discard > 0 {
		copy(this.tail[:], this.tail[discard:this.length])
		this.length -= discard
		this.truncated = true
	}
	copy(this.tail[this.length:], data)
	this.length += length
	return length, nil
}

func (this *localConPTYRelayStatusWriter) exitStatus() (int, string, error) {
	data := this.tail[:this.length]
	diagnostic := func(raw []byte) string {
		result := strings.TrimSpace(string(raw))
		if this.truncated {
			return "[truncated] " + result
		}
		return result
	}
	footerLength := len(localConPTYRelayExitPrefix) + 8 + 1
	if len(data) < footerLength || !bytes.HasPrefix(data[len(data)-footerLength:], []byte(localConPTYRelayExitPrefix)) || data[len(data)-1] != '\n' {
		return 0, diagnostic(data), fmt.Errorf("missing ConPTY relay exit status")
	}
	start := len(data) - footerLength
	if bytes.Contains(data[:start], []byte(localConPTYRelayExitPrefix)) {
		return 0, diagnostic(data), fmt.Errorf("duplicate ConPTY relay exit status")
	}
	digits := data[start+len(localConPTYRelayExitPrefix) : len(data)-1]
	for _, digit := range digits {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return 0, diagnostic(data), fmt.Errorf("invalid ConPTY relay exit status")
		}
	}
	value, err := strconv.ParseUint(string(digits), 16, 32)
	if err != nil {
		return 0, diagnostic(data), fmt.Errorf("invalid ConPTY relay exit status: %w", err)
	}
	return int(value), diagnostic(data[:start]), nil
}

func (this *local) runConPTY(t Task, shell *exec.Cmd) (int, error) {
	fail := func(format string, args ...any) (int, error) {
		return -1, fmt.Errorf("cannot run local ConPTY: "+format, args...)
	}
	if shell.SysProcAttr == nil || shell.SysProcAttr.Token == 0 {
		return fail("missing local account token")
	}
	pty, sizes, ok := t.SshSession().Pty()
	if !ok {
		return fail("missing SSH PTY request")
	}
	if err := localConPTYSize(pty.Window); err != nil {
		return fail("%w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fail("resolve relay executable: %w", err)
	}
	if shell.Path == "" || len(shell.Args) == 0 {
		return fail("missing shell command")
	}
	args := append([]string(nil), shell.Args...)
	args[0] = shell.Path
	encoded, err := json.Marshal(args)
	if err != nil {
		return fail("encode shell command: %w", err)
	}
	relay := exec.Command(exe, "local-conpty-relay", strconv.Itoa(pty.Window.Width), strconv.Itoa(pty.Window.Height))
	relay.Dir = shell.Dir
	relay.Env = shell.Env
	relay.SysProcAttr = &syscall.SysProcAttr{Token: shell.SysProcAttr.Token}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		return fail("open relay output pipe: %w", err)
	}
	defer outputRead.Close()
	defer outputWrite.Close()
	relay.Stdout = outputWrite
	status := &localConPTYRelayStatusWriter{}
	relay.Stderr = status
	control, err := relay.StdinPipe()
	if err != nil {
		return fail("open relay control pipe: %w", err)
	}
	if err := relay.Start(); err != nil {
		_ = control.Close()
		return fail("start relay as %q: %w", this.user.Name, err)
	}
	_ = outputWrite.Close()
	t.Connection().Logger().With("pid", relay.Process.Pid).Debug("local ConPTY relay started")

	outputDone := make(chan error, 1)
	outputWriter := &localConPTYOutputWriter{Writer: t.SshSession()}
	go func() {
		_, err := io.Copy(outputWriter, outputRead)
		outputDone <- err
	}()
	const outputTimeout = 2 * time.Second
	outputWatch := time.NewTicker(100 * time.Millisecond)
	defer outputWatch.Stop()
	stop := make(chan struct{})
	frames := make(chan localConPTYFrame, 8)
	resizes := make(chan localConPTYFrame, 1)
	processDone := make(chan error, 1)
	waitFinished := make(chan struct{})
	outputDrained := false
	go func() {
		defer close(waitFinished)
		processDone <- relay.Wait()
	}()
	defer func() {
		close(stop)
		_ = control.Close()
		_ = outputRead.Close()
		if !outputDrained {
			go func() { _ = t.SshSession().Close() }()
		}
		_ = relay.Process.Kill()
		<-waitFinished
	}()

	go func() {
		defer control.Close()
		if err := writeLocalConPTYFrame(control, localConPTYFrame{kind: 'C', data: encoded}); err != nil {
			return
		}
		for {
			select {
			case <-stop:
				return
			case frame := <-frames:
				if err := writeLocalConPTYFrame(control, frame); err != nil {
					return
				}
			case frame := <-resizes:
				if err := writeLocalConPTYFrame(control, frame); err != nil {
					return
				}
			}
		}
	}()
	inputDone := make(chan error, 1)
	go func() {
		var buf [32768]byte
		for {
			n, err := t.SshSession().Read(buf[:])
			if n > 0 {
				frame := localConPTYFrame{kind: 'D', data: append([]byte(nil), buf[:n]...)}
				select {
				case frames <- frame:
				case <-stop:
					return
				}
			}
			if err != nil {
				// Closing the ConPTY input pipe on SSH half-close also closes the console.
				// Keep the control pipe open until the shell exits so output is not lost.
				inputDone <- err
				return
			}
		}
	}()
	signals := make(chan essh.Signal, 1)
	t.SshSession().Signals(signals)
	defer t.SshSession().Signals(nil)
	for {
		select {
		case <-t.Context().Done():
			return -2, nil
		case err := <-processDone:
			if t.Context().Err() != nil {
				return -2, nil
			}
			if outputDone != nil {
				timer := time.NewTimer(outputTimeout)
				defer timer.Stop()
				select {
				case outputErr := <-outputDone:
					if t.Context().Err() != nil {
						return -2, nil
					}
					if outputErr != nil {
						_, diagnostic, _ := status.exitStatus()
						if err != nil {
							return fail("relay exited: %w; output forwarding failed: %v (stderr: %s)", err, outputErr, diagnostic)
						}
						return fail("forward relay output: %w (relay stderr: %s)", outputErr, diagnostic)
					}
				case <-timer.C:
					if t.Context().Err() != nil {
						return -2, nil
					}
					if err != nil {
						_, diagnostic, _ := status.exitStatus()
						return fail("relay exited: %w; output did not drain within %s (stderr: %s)", err, outputTimeout, diagnostic)
					}
					return fail("relay output did not drain within %s", outputTimeout)
				case <-t.Context().Done():
					return -2, nil
				}
			}
			outputDrained = true
			code, diagnostic, statusErr := status.exitStatus()
			if err != nil {
				return fail("relay exited: %w (stderr: %s)", err, diagnostic)
			}
			if statusErr != nil {
				return fail("relay status: %w (stderr: %s)", statusErr, diagnostic)
			}
			if diagnostic != "" {
				t.Connection().Logger().With("stderr", diagnostic).Warn("ConPTY relay reported diagnostics")
			}
			return code, nil
		case err := <-outputDone:
			outputDone = nil
			if err != nil {
				if t.Context().Err() != nil {
					return -2, nil
				}
				_ = relay.Process.Kill()
				<-waitFinished
				_, diagnostic, _ := status.exitStatus()
				return fail("forward relay output: %w (relay stderr: %s)", err, diagnostic)
			}
		case <-outputWatch.C:
			if started := outputWriter.writingSince.Load(); started != nil && time.Since(*started) >= outputTimeout {
				if t.Context().Err() != nil {
					return -2, nil
				}
				return fail("SSH output write did not finish within %s", outputTimeout)
			}
		case err := <-inputDone:
			inputDone = nil
			if err != nil && !errors.Is(err, io.EOF) {
				return fail("read SSH input: %w", err)
			}
		case win, open := <-sizes:
			if !open {
				sizes = nil
				continue
			}
			if err := localConPTYSize(win); err != nil {
				t.Connection().Logger().WithError(err).Warn("invalid ConPTY resize; ignoring")
				continue
			}
			frame := localConPTYFrame{kind: 'R', data: []byte{byte(win.Width), byte(win.Width >> 8), byte(win.Height), byte(win.Height >> 8)}}
			select {
			case resizes <- frame:
			default:
				select {
				case <-resizes:
				default:
				}
				resizes <- frame
			}
		case signal, open := <-signals:
			if !open {
				signals = nil
				continue
			}
			switch signal {
			case "INT":
				select {
				case frames <- localConPTYFrame{kind: 'D', data: []byte{3}}:
				default:
					t.Connection().Logger().Warn("ConPTY control pipe is busy; interrupt dropped")
				}
			case "HUP", "TERM", "KILL":
				return -2, nil
			default:
				t.Connection().Logger().With("signal", signal).Warn("unsupported SSH signal for ConPTY")
			}
		}
	}
}

func localConPTYSize(win essh.Window) error {
	if win.Width < 1 || win.Width > 32767 || win.Height < 1 || win.Height > 32767 {
		return fmt.Errorf("invalid PTY size %d x %d", win.Width, win.Height)
	}
	return nil
}

func writeLocalConPTYFrame(out io.Writer, frame localConPTYFrame) error {
	var header [5]byte
	header[0] = frame.kind
	binary.LittleEndian.PutUint32(header[1:], uint32(len(frame.data)))
	if _, err := out.Write(header[:]); err != nil {
		return err
	}
	if len(frame.data) > 0 {
		_, err := out.Write(frame.data)
		return err
	}
	return nil
}
