//go:build windows

package environment

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	essh "github.com/engity-com/ssh-server-go"
)

type localConPTYFrame struct {
	kind byte
	data []byte
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
	relay.Stdout = t.SshSession()
	relay.Stderr = &log.LoggingWriter{Logger: t.Connection().Logger(), LevelExtractor: level.FixedLevelExtractor(level.Error)}
	control, err := relay.StdinPipe()
	if err != nil {
		return fail("open relay control pipe: %w", err)
	}
	if err := relay.Start(); err != nil {
		_ = control.Close()
		return fail("start relay as %q: %w", this.user.Name, err)
	}
	t.Connection().Logger().With("pid", relay.Process.Pid).Debug("local ConPTY relay started")

	stop := make(chan struct{})
	frames := make(chan localConPTYFrame, 8)
	resizes := make(chan localConPTYFrame, 1)
	processDone := make(chan error, 1)
	waitFinished := make(chan struct{})
	exitObserved := false
	go func() {
		defer close(waitFinished)
		processDone <- relay.Wait()
	}()
	defer func() {
		close(stop)
		_ = control.Close()
		if !exitObserved {
			_ = t.SshSession().Close()
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
			exitObserved = true
			if err == nil {
				return 0, nil
			}
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return exit.ExitCode(), nil
			}
			return fail("relay exited: %w", err)
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
