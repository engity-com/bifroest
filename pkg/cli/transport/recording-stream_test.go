package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/recording"
)

func TestRecordingStreamYieldsBeforeCompletionAndRequiresEnd(t *testing.T) {
	var encoded bytes.Buffer
	entry := model.RecordingView{ID: "00000001-0000-4000-8000-000000000000", Auditlog: "default"}
	require.NoError(t, WriteRecordingStreamEntry(&encoded, entry))
	partial := bytes.Clone(encoded.Bytes())
	var rows []model.RecordingView
	err := DecodeRecordingListStream(bytes.NewReader(partial), func(row model.RecordingView) error {
		rows = append(rows, row)
		return nil
	})
	require.ErrorContains(t, err, "before its completion frame")
	require.Equal(t, []model.RecordingView{entry}, rows)
	require.NoError(t, WriteRecordingStreamEnd(&encoded, 1))
	rows = nil
	require.NoError(t, DecodeRecordingListStream(&encoded, func(row model.RecordingView) error {
		rows = append(rows, row)
		return nil
	}))
	require.Equal(t, []model.RecordingView{entry}, rows)
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
		require.Error(t, DecodeRecordingListStream(&encoded, func(model.RecordingView) error { return nil }))
	}
	var failed bytes.Buffer
	require.NoError(t, WriteRecordingStreamEntry(&failed, model.RecordingView{ID: "verified-prefix"}))
	require.NoError(t, WriteRecordingStreamError(&failed, errors.New("artifact verification failed")))
	seen := 0
	err := DecodeRecordingListStream(&failed, func(model.RecordingView) error { seen++; return nil })
	require.ErrorContains(t, err, "artifact verification failed")
	require.Equal(t, 1, seen)
}

func TestRecordingStreamBoundsEntryCountAndStopsOnConsumerFailure(t *testing.T) {
	var encoded bytes.Buffer
	for range recording.MaximumSealedPageSize + 1 {
		require.NoError(t, WriteRecordingStreamEntry(&encoded, model.RecordingView{}))
	}
	data := bytes.Clone(encoded.Bytes())
	seen := 0
	err := DecodeRecordingListStream(&encoded, func(model.RecordingView) error { seen++; return nil })
	require.ErrorContains(t, err, "maximum page size")
	require.Equal(t, int(recording.MaximumSealedPageSize), seen)
	failure := errors.New("local output failed")
	err = DecodeRecordingListStream(bytes.NewReader(data), func(model.RecordingView) error { return failure })
	require.ErrorIs(t, err, failure)
}

type shortRecordingStreamWriter struct{}

func (shortRecordingStreamWriter) Write([]byte) (int, error) { return 0, nil }

func TestRecordingStreamReportsShortWrites(t *testing.T) {
	require.ErrorIs(t, WriteRecordingStreamEnd(shortRecordingStreamWriter{}, 0), io.ErrShortWrite)
}
