package service

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

func TestShellBannerTextPreservesExistingControlsAndChunkBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"empty", "", ""},
		{"LF", "one\n\ntwo\n", "one\r\n\r\ntwo\r\n"},
		{"CRLF", "one\r\n\r\ntwo\r\n", "one\r\n\r\ntwo\r\n"},
		{"bare CR and escapes", "\x1b[31mone\rtwo\n\x1b[0m", "\x1b[31mone\rtwo\r\n\x1b[0m"},
		{"raw bytes", "a\x00\xff\n", "a\x00\xff\r\n"},
		{"source buffer boundary", strings.Repeat("x", 4095) + "\r\n\n尾\r", strings.Repeat("x", 4095) + "\r\n\r\n尾\r"},
	} {
		for _, size := range []int{1, 2, 7, 8192} {
			t.Run(tc.name+"/buffer-"+strconv.Itoa(size), func(t *testing.T) {
				for _, source := range []io.Reader{strings.NewReader(tc.input), iotest.OneByteReader(strings.NewReader(tc.input)), iotest.DataErrReader(strings.NewReader(tc.input))} {
					reader := &bannerTextReader{source: source}
					var out bytes.Buffer
					buffer := make([]byte, size)
					for {
						n, err := reader.Read(buffer)
						out.Write(buffer[:n])
						if err != nil {
							require.ErrorIs(t, err, io.EOF)
							break
						}
					}
					require.Equal(t, tc.want, out.String())
				}
			})
		}
		var raw bytes.Buffer
		_, err := copyShellBanner(&raw, strings.NewReader(tc.input), false)
		require.NoError(t, err)
		require.Equal(t, tc.input, raw.String(), "non-PTY text remains byte-exact")
	}
}

type bannerTextFailWriter struct {
	calls   int
	failure error
	short   bool
}

func (w *bannerTextFailWriter) Write(data []byte) (int, error) {
	w.calls++
	if w.short {
		return len(data) - 1, nil
	}
	return 0, w.failure
}

func TestShellBannerTextPropagatesDeliveryAndReadFailuresWithoutRetry(t *testing.T) {
	failure := errors.New("fixture banner failure")
	for _, short := range []bool{false, true} {
		writer := &bannerTextFailWriter{failure: failure, short: short}
		_, err := copyShellBanner(writer, strings.NewReader("one\n"), true)
		if short {
			require.ErrorIs(t, err, io.ErrShortWrite)
		} else {
			require.ErrorIs(t, err, failure)
		}
		require.Equal(t, 1, writer.calls)
	}
	_, err := copyShellBanner(io.Discard, iotest.ErrReader(failure), true)
	require.ErrorIs(t, err, failure)
}
