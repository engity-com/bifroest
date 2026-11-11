//go:build windows

package environment

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// Diagnostic comparison with the unchanged stdlib-output fixture. Keep this
// inside test code; applications still choose their own real console I/O.
func writeLocalTestConsoleNative(file *os.File, text string) (int, error) {
	data, err := windows.UTF16FromString(text)
	if err != nil {
		return 0, err
	}
	var written uint32
	err = windows.WriteConsole(windows.Handle(file.Fd()), &data[0], uint32(len(data)-1), &written, nil)
	if err != nil {
		return 0, err
	}
	if written != uint32(len(data)-1) {
		return 0, io.ErrShortWrite
	}
	return len(text), nil
}

func writeLocalTestConsoleFile(file *os.File, text string) (int, error) {
	var written uint32
	err := windows.WriteFile(windows.Handle(file.Fd()), []byte(text), &written, nil)
	if err == nil && int(written) != len(text) {
		err = io.ErrShortWrite
	}
	return int(written), err
}

func TestLocalConPTYNativeConsoleDiagnosticDoesNotFallBackToPipeWrites(t *testing.T) {
	var input, output windows.Handle
	require.NoError(t, windows.CreatePipe(&input, &output, nil, 0))
	t.Cleanup(func() { require.NoError(t, windows.CloseHandle(input)) })
	file := os.NewFile(uintptr(output), "owned-native-diagnostic-pipe")
	require.NotNil(t, file)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	written, err := writeLocalTestConsoleNative(file, "must require a real console")
	require.Error(t, err)
	require.Zero(t, written)
}

func TestLocalConPTYRawFileDiagnosticPreservesItsExactBytes(t *testing.T) {
	var input, output windows.Handle
	require.NoError(t, windows.CreatePipe(&input, &output, nil, 0))
	t.Cleanup(func() { require.NoError(t, windows.CloseHandle(input)) })
	file := os.NewFile(uintptr(output), "owned-raw-diagnostic-pipe")
	require.NotNil(t, file)
	wanted := "raw bytes\x00\xff\r\n"
	written, writeErr := writeLocalTestConsoleFile(file, wanted)
	closeErr := file.Close()
	require.NoError(t, writeErr)
	require.NoError(t, closeErr)
	require.Equal(t, len(wanted), written)
	actual, err := io.ReadAll(&localConPTYOutputReader{handle: input})
	require.NoError(t, err)
	require.Equal(t, []byte(wanted), actual)
}
