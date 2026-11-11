package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/stretchr/testify/require"
)

func TestTransferWriterRequiresSeparatePostDriverCompletion(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	var output bytes.Buffer
	writer, err := NewTransferWriter(&output, request)
	require.NoError(t, err)
	require.Error(t, writer.Complete())
	require.Empty(t, output.Bytes())
	data := bytes.Repeat([]byte{'x'}, MaximumTransferFrameBytes+1)
	n, err := writer.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	require.NoError(t, writer.EndData())
	prefix := bytes.Clone(output.Bytes())
	require.Error(t, writer.EndData())
	_, err = writer.Write([]byte("late"))
	require.Error(t, err)
	require.Equal(t, prefix, output.Bytes())
	require.NoError(t, writer.Complete())
	require.Greater(t, output.Len(), len(prefix))
	completed := bytes.Clone(output.Bytes())
	require.Error(t, writer.Complete())
	require.Equal(t, completed, output.Bytes())
}

type failedTransferWriter struct {
	err   error
	calls int
}

func (this *failedTransferWriter) Write([]byte) (int, error) { this.calls++; return 0, this.err }

func TestTransferWriterBoundsDataAndNeverRetriesFailedOutput(t *testing.T) {
	request := protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
	var output bytes.Buffer
	writer, err := NewTransferWriter(&output, request)
	require.NoError(t, err)
	writer.maximum = 2
	_, err = writer.Write([]byte("too much"))
	require.Error(t, err)
	require.Empty(t, output.Bytes())
	require.Error(t, writer.EndData())
	require.Error(t, writer.Complete())
	failure := errors.New("delivery failed")
	sink := &failedTransferWriter{err: failure}
	writer, err = NewTransferWriter(sink, request)
	require.NoError(t, err)
	_, err = writer.Write([]byte("data"))
	require.ErrorIs(t, err, failure)
	require.ErrorIs(t, writer.EndData(), failure)
	require.ErrorIs(t, writer.Complete(), failure)
	require.Equal(t, 1, sink.calls)
	writer, err = NewTransferWriter(shortRecordingStreamWriter{}, request)
	require.NoError(t, err)
	_, err = writer.Write([]byte("x"))
	require.ErrorIs(t, err, io.ErrShortWrite)
}
