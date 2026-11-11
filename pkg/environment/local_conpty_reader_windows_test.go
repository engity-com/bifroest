//go:build windows

package environment

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLocalConPTYOutputReadKeepsEmptyMessagesDistinctFromEOF(t *testing.T) {
	count, err := localConPTYOutputReadResult(0, nil)
	require.Zero(t, count)
	require.NoError(t, err, "a successful empty message is not stream completion")
	count, err = localConPTYOutputReadResult(3, nil)
	require.Equal(t, 3, count)
	require.NoError(t, err)
	count, err = localConPTYOutputReadResult(0, windows.ERROR_BROKEN_PIPE)
	require.Zero(t, count)
	require.ErrorIs(t, err, io.EOF)
	for _, failure := range []error{windows.ERROR_OPERATION_ABORTED, windows.ERROR_NO_DATA, windows.ERROR_ACCESS_DENIED} {
		_, err := localConPTYOutputReadResult(0, failure)
		require.ErrorIs(t, err, failure)
		require.NotErrorIs(t, err, io.EOF, "I/O failure must not become optimistic completion")
	}
}

func TestLocalConPTYOutputPipeKeepsEmptyWritesAndBinaryOutput(t *testing.T) {
	var input, output windows.Handle
	require.NoError(t, windows.CreatePipe(&input, &output, nil, 0))
	t.Cleanup(func() { require.NoError(t, windows.CloseHandle(input)) })
	wanted := []byte("pipe-data\x00\xff\xe2\x82\xac\r\n")
	done := make(chan error, 1)
	go func() {
		write := func(data []byte) error {
			var written uint32
			if err := windows.WriteFile(output, data, &written, nil); err != nil {
				return err
			}
			if int(written) != len(data) {
				return io.ErrShortWrite
			}
			return nil
		}
		err := write(nil)
		if err == nil {
			err = write(wanted)
		}
		done <- errors.Join(err, windows.CloseHandle(output))
	}()
	var actual bytes.Buffer
	count, err := io.Copy(&actual, &localConPTYOutputReader{handle: input})
	require.NoError(t, err)
	require.EqualValues(t, len(wanted), count)
	require.Equal(t, wanted, actual.Bytes())
	require.NoError(t, <-done)
}

func TestLocalConPTYOutputNativeEOFObservationsDoNotChangeReadResults(t *testing.T) {
	for _, closing := range []bool{false, true} {
		var input, output windows.Handle
		require.NoError(t, windows.CreatePipe(&input, &output, nil, 0))
		t.Cleanup(func() { require.NoError(t, windows.CloseHandle(input)) })
		require.NoError(t, windows.CloseHandle(output))
		var observation localConPTYRelayObservation
		reader := &localConPTYOutputReader{handle: input, observation: &observation}
		reader.rootProcess.Store(uintptr(windows.CurrentProcess()))
		reader.closeStarted.Store(closing)
		count, err := reader.Read(make([]byte, 16))
		require.Zero(t, count)
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, !closing, observation.eofBeforeClose)
		require.Equal(t, "running", observation.rootAtNativeEOF)
	}
}
