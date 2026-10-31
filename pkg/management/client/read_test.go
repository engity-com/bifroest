package client

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
	"github.com/stretchr/testify/require"
)

func TestReadBytesBoundsAbortBeforeWaitingForTheProducer(t *testing.T) {
	for _, maximum := range []int64{2, -1, math.MaxInt64} {
		response := &testResponse{input: bytes.NewReader([]byte("too large"))}
		value, err := ReadBytes(t.Context(), response, maximum)
		require.Error(t, err)
		require.Nil(t, value)
		require.Equal(t, []string{"abort", "complete", "close"}, response.snapshot())
	}
}

func TestReadRecordingListKeepsCallbacksProvisionalThroughEndAndCompletion(t *testing.T) {
	var encoded bytes.Buffer
	entry := protocol.RecordingView{ID: "recording"}
	require.NoError(t, wire.WriteRecordingStreamEntry(&encoded, entry))
	partial := bytes.Clone(encoded.Bytes())
	require.NoError(t, wire.WriteRecordingStreamEnd(&encoded, 1))
	finalErr := errors.New("task sealing failed")
	for _, test := range []struct {
		data     []byte
		complete error
	}{{partial, nil}, {encoded.Bytes(), finalErr}} {
		response := &testResponse{input: bytes.NewReader(test.data), complete: func() error { return test.complete }}
		var seen []protocol.RecordingView
		err := ReadRecordingList(t.Context(), response, func(row protocol.RecordingView) error { seen = append(seen, row); return nil })
		require.Error(t, err)
		require.Equal(t, []protocol.RecordingView{entry}, seen, "callback delivery is not full success")
		if test.complete != nil {
			require.ErrorIs(t, err, finalErr)
		}
		require.Contains(t, response.snapshot(), "abort")
		require.Equal(t, "close", response.snapshot()[2])
	}
}

func TestReadRecordingRequiresSelectorAndFinalCompletionWithoutPublishingHeader(t *testing.T) {
	content := []byte("opaque recording bytes")
	header := wire.RecordingArtifactHeader{Version: 1, ID: "recording", ProducerID: "untrusted", Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	var encoded bytes.Buffer
	require.NoError(t, wire.WriteRecordingArtifact(&encoded, header, bytes.NewReader(content)))
	finalErr := errors.New("task final audit failed")
	for _, test := range []struct {
		id       string
		complete error
		success  bool
	}{{"recording", nil, true}, {"other", nil, false}, {"recording", finalErr, false}, {"", nil, false}} {
		var provisional bytes.Buffer
		response := &testResponse{input: bytes.NewReader(encoded.Bytes()), complete: func() error { return test.complete }}
		actual, err := ReadRecording(t.Context(), response, test.id, &provisional, 4096)
		if test.success {
			require.NoError(t, err)
			require.Equal(t, header, actual)
		} else {
			require.Error(t, err)
			require.Equal(t, wire.RecordingArtifactHeader{}, actual)
		}
		if test.complete != nil {
			require.ErrorIs(t, err, finalErr)
		}
		if test.id != "" {
			require.Equal(t, content, provisional.Bytes())
		}
	}
}

type auditMemorySink struct {
	files  map[string]*bytes.Buffer
	closes int
}
type auditMemoryWriter struct {
	io.Writer
	close func()
}

func (this *auditMemoryWriter) Close() error { this.close(); return nil }
func (this *auditMemorySink) Begin(wire.AuditSnapshotHeader) error {
	this.files = map[string]*bytes.Buffer{}
	return nil
}
func (this *auditMemorySink) Open(entry wire.AuditSnapshotEntry) (io.WriteCloser, error) {
	out := &bytes.Buffer{}
	this.files[entry.Name] = out
	return &auditMemoryWriter{out, func() { this.closes++ }}, nil
}

func TestReadAuditSnapshotKeepsSinkProvisionalAndMatchesExpectedSelector(t *testing.T) {
	content := []byte("opaque head bytes")
	header := wire.AuditSnapshotHeader{Version: 1, Name: "default", Producer: strings.Repeat("a", 64), Files: []wire.AuditSnapshotEntry{{Name: "head.cbor", Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}}}
	var encoded bytes.Buffer
	require.NoError(t, wire.WriteAuditSnapshotHeader(&encoded, header))
	encoded.Write(content)
	finalErr := errors.New("task final audit failed")
	for _, test := range []struct {
		name     string
		complete error
		success  bool
	}{{"default", nil, true}, {"other", nil, false}, {"default", finalErr, false}} {
		sink := &auditMemorySink{}
		response := &testResponse{input: bytes.NewReader(encoded.Bytes()), complete: func() error { return test.complete }}
		actual, err := ReadAuditSnapshot(t.Context(), response, test.name, sink)
		if test.success {
			require.NoError(t, err)
			require.Equal(t, header, actual)
		} else {
			require.Error(t, err)
			require.Equal(t, wire.AuditSnapshotHeader{}, actual)
		}
		require.Equal(t, content, sink.files["head.cbor"].Bytes())
		require.Equal(t, 1, sink.closes)
		if test.complete != nil {
			require.ErrorIs(t, err, finalErr)
		}
	}
}
