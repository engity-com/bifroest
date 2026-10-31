package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/management/protocol"
)

func TestRecordingStreamYieldsBeforeCompletionAndRequiresEnd(t *testing.T) {
	var encoded bytes.Buffer
	entry := protocol.RecordingView{ID: "00000001-0000-4000-8000-000000000000", Auditlog: "default"}
	require.NoError(t, WriteRecordingStreamEntry(&encoded, entry))
	partial := bytes.Clone(encoded.Bytes())
	var rows []protocol.RecordingView
	err := DecodeRecordingListStream(bytes.NewReader(partial), func(row protocol.RecordingView) error {
		rows = append(rows, row)
		return nil
	})
	require.ErrorContains(t, err, "before its completion frame")
	require.Equal(t, []protocol.RecordingView{entry}, rows)
	require.NoError(t, WriteRecordingStreamEnd(&encoded, 1))
	rows = nil
	require.NoError(t, DecodeRecordingListStream(&encoded, func(row protocol.RecordingView) error {
		rows = append(rows, row)
		return nil
	}))
	require.Equal(t, []protocol.RecordingView{entry}, rows)
}

func TestRecordingStreamRejectsIncompleteInvalidAndFailedStreams(t *testing.T) {
	for _, build := range []func(*bytes.Buffer){
		func(*bytes.Buffer) {},
		func(out *bytes.Buffer) { out.Write([]byte{0, 0}) },
		func(out *bytes.Buffer) { out.Write([]byte{0, 0, 0, 0}) },
		func(out *bytes.Buffer) {
			var size [4]byte
			binary.BigEndian.PutUint32(size[:], maximumRecordingStreamFrameBytes+1)
			out.Write(size[:])
		},
		func(out *bytes.Buffer) { out.Write([]byte{0, 0, 0, 4, 1}) },
		func(out *bytes.Buffer) { require.NoError(t, WriteRecordingStreamEnd(out, 1)) },
		func(out *bytes.Buffer) {
			require.NoError(t, WriteRecordingStreamEnd(out, 0))
			out.WriteByte(1)
		},
		func(out *bytes.Buffer) { require.NoError(t, writeRecordingStreamFrame(out, 255, nil)) },
	} {
		var encoded bytes.Buffer
		build(&encoded)
		require.Error(t, DecodeRecordingListStream(&encoded, func(protocol.RecordingView) error { return nil }))
	}
	var failed bytes.Buffer
	require.NoError(t, WriteRecordingStreamEntry(&failed, protocol.RecordingView{ID: "verified-prefix"}))
	require.NoError(t, WriteRecordingStreamError(&failed, errors.New("artifact verification failed")))
	seen := 0
	err := DecodeRecordingListStream(&failed, func(protocol.RecordingView) error { seen++; return nil })
	require.ErrorContains(t, err, "artifact verification failed")
	require.Equal(t, 1, seen)
}

func TestRecordingStreamBoundsEntryCountAndStopsOnConsumerFailure(t *testing.T) {
	var encoded bytes.Buffer
	for range protocol.MaximumRecordingPageSize + 1 {
		require.NoError(t, WriteRecordingStreamEntry(&encoded, protocol.RecordingView{}))
	}
	data := bytes.Clone(encoded.Bytes())
	seen := 0
	err := DecodeRecordingListStream(&encoded, func(protocol.RecordingView) error { seen++; return nil })
	require.ErrorContains(t, err, "maximum page size")
	require.Equal(t, int(protocol.MaximumRecordingPageSize), seen)
	failure := errors.New("local output failed")
	err = DecodeRecordingListStream(bytes.NewReader(data), func(protocol.RecordingView) error { return failure })
	require.ErrorIs(t, err, failure)
}

type shortRecordingStreamWriter struct{}

func (shortRecordingStreamWriter) Write([]byte) (int, error) { return 0, nil }

func TestRecordingStreamReportsShortWrites(t *testing.T) {
	require.ErrorIs(t, WriteRecordingStreamEnd(shortRecordingStreamWriter{}, 0), io.ErrShortWrite)
}
