package management

import (
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestManagementConsoleWindows(t *testing.T) {
	binary, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestManagementConsoleWindowsProcess$")
	command.Env = append(os.Environ(), "BIFROEST_TEST_CONSOLE_WINDOWS_CHILD=1")
	// Never change the terminal or consume input belonging to the test runner.
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.NoError(t, ctx.Err())
}

func TestManagementConsoleWindowsProcess(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_CONSOLE_WINDOWS_CHILD") != "1" {
		return
	}
	allocated, _, err := consoleKernel32.NewProc("AllocConsole").Call()
	require.NotZero(t, allocated, "%v", err)
	t.Cleanup(func() { _, _, _ = consoleKernel32.NewProc("FreeConsole").Call() })
	path, err := windows.UTF16PtrFromString("CONIN$")
	require.NoError(t, err)
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	require.NoError(t, err)
	terminal := os.NewFile(uintptr(handle), "test console")
	t.Cleanup(func() { _ = terminal.Close() })
	var original uint32
	require.NoError(t, windows.GetConsoleMode(handle, &original))
	require.Equal(t, uintptr(20), unsafe.Sizeof(consoleInputRecord{}))
	writeInput := func(t *testing.T, text string) {
		t.Helper()
		encoded := utf16.Encode([]rune(text))
		var records []consoleInputRecord
		for _, character := range encoded {
			if len(records) > 0 && records[len(records)-1].key.character == character && records[len(records)-1].key.repeat < 65535 {
				records[len(records)-1].key.repeat++
			} else {
				records = append(records, consoleInputRecord{kind: 1, key: consoleKeyEvent{down: 1, repeat: 1, character: character}})
			}
		}
		var written uint32
		success, _, err := consoleKernel32.NewProc("WriteConsoleInputW").Call(uintptr(handle), uintptr(unsafe.Pointer(&records[0])), uintptr(len(records)), uintptr(unsafe.Pointer(&written)))
		runtime.KeepAlive(records)
		runtime.KeepAlive(&written)
		require.NotZero(t, success, "%v", err)
		require.Equal(t, uint32(len(records)), written)
	}
	checkRestored := func(t *testing.T) {
		t.Helper()
		var after uint32
		require.NoError(t, windows.GetConsoleMode(handle, &after), "borrowed console must remain open")
		require.Equal(t, original, after)
	}
	for _, test := range []struct {
		name   string
		input  string
		echo   bool
		cancel bool
		want   string
		err    error
	}{
		{name: "secret unicode and backspace", input: "sëcretX\b😀\r", want: "sëcret😀"},
		{name: "visible answer", input: "alice\r", echo: true, want: "alice"},
		{name: "cancel blocked read", cancel: true, err: context.Canceled},
		{name: "cancel incomplete secret", input: "discard this", cancel: true, err: context.Canceled},
		{name: "fresh after cancellation", input: "fresh\r", want: "fresh"},
		{name: "CtrlC", input: "\x03", err: context.Canceled},
		{name: "EOF", input: "\x04", err: io.EOF},
		{name: "bounded input", input: strings.Repeat("a", maximumConsoleInputBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := newConsoleTestOutput()
			ctx, cancel := context.WithCancel(cli.ContextWithStdio(t.Context(), terminal, io.Discard, output))
			defer cancel()
			done := make(chan consoleTestResult, 1)
			go func() {
				line, err := readManagementLine(ctx, "Answer: ", test.echo)
				done <- consoleTestResult{line, err}
			}()
			output.await(t, "Answer: ")
			if test.input != "" {
				writeInput(t, test.input)
			}
			if test.cancel {
				// Exercise cancellation while the native synchronous read is pending.
				time.Sleep(50 * time.Millisecond)
				cancel()
			}
			result := awaitConsoleTestResult(t, done)
			if test.err != nil {
				require.ErrorIs(t, result.err, test.err)
				require.Nil(t, result.line)
			} else if test.name == "bounded input" {
				require.ErrorContains(t, result.err, "input exceeds")
				require.Nil(t, result.line)
			} else {
				require.NoError(t, result.err)
				require.Equal(t, test.want, string(result.line))
				clear(result.line)
			}
			if test.echo {
				require.Contains(t, output.String(), test.want+"\n")
			} else if test.want != "" {
				require.NotContains(t, output.String(), test.want)
			}
			checkRestored(t)
		})
	}
	t.Run("borrowed input remains readable", func(t *testing.T) {
		writeInput(t, "x")
		done := make(chan struct {
			record consoleInputRecord
			err    error
		}, 1)
		go func() {
			record, err := (&consoleInput{handle: handle}).nextRecord()
			done <- struct {
				record consoleInputRecord
				err    error
			}{record, err}
		}()
		select {
		case result := <-done:
			require.NoError(t, result.err)
			require.Equal(t, uint16('x'), result.record.key.character)
		case <-time.After(3 * time.Second):
			t.Fatal("borrowed input no longer receives console events")
		}
		checkRestored(t)
	})
	t.Run("console output is not a terminal input", func(t *testing.T) {
		path, err := windows.UTF16PtrFromString("CONOUT$")
		require.NoError(t, err)
		handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		require.NoError(t, err)
		outputTerminal := os.NewFile(uintptr(handle), "test console output")
		defer func() { require.NoError(t, outputTerminal.Close()) }()
		output := newConsoleTestOutput()
		ctx := cli.ContextWithStdio(t.Context(), outputTerminal, io.Discard, output)
		line, err := readManagementPassword(ctx, "Password: ")
		require.Error(t, err)
		require.Nil(t, line)
		require.Empty(t, output.String())
	})
}
