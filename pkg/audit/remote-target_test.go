package audit

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealedSegmentMetadataAndRemotePath(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	require.NoError(t, segment.Validate())
	require.Equal(t, ProducerId{1}, segment.ProducerId())
	require.Equal(t, uint64(42), segment.Sequence())
	require.Equal(t, int64(len("sealed segment")), segment.Size())
	require.Equal(t, "segment-00000000000000000042-"+segment.Hash().String()+".journal", segment.FileName())
	require.Equal(t, segment.ProducerId().String()+"/"+segment.FileName(), segment.RemotePath())
	require.NotContains(t, segment.RemotePath(), `\`)
	first, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	second, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestSealedSegmentValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SealedSegment)
		err    string
	}{
		{"producer", func(value *SealedSegment) { value.producerId = ProducerId{} }, "producer ID"},
		{"sequence", func(value *SealedSegment) { value.sequence = 0 }, "sequence"},
		{"hash", func(value *SealedSegment) { value.hash = SegmentHash{} }, "hash"},
		{"zero-size", func(value *SealedSegment) { value.size = 0 }, "size"},
		{"negative-size", func(value *SealedSegment) { value.size = -1 }, "size"},
		{"short-size", func(value *SealedSegment) { value.size-- }, "exceeds declared size"},
		{"long-size", func(value *SealedSegment) { value.size++ }, "content size"},
		{"wrong-hash", func(value *SealedSegment) { value.hash[0]++ }, "does not match hash"},
		{"content", func(value *SealedSegment) { value.content = nil }, "content"},
		{"typed-nil-content", func(value *SealedSegment) { value.content = (*bytes.Reader)(nil) }, "content"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			segment := validRemoteTargetTestSegment()
			test.mutate(&segment)
			require.ErrorContains(t, segment.Validate(), test.err)
		})
	}
}

func TestSegmentHashText(t *testing.T) {
	expected := SegmentHash{1, 2, 3}
	var actual SegmentHash
	require.NoError(t, actual.UnmarshalText([]byte(expected.String())))
	require.Equal(t, expected, actual)
	require.Error(t, actual.UnmarshalText([]byte("short")))
	require.Error(t, actual.UnmarshalText([]byte(strings.Repeat("z", 64))))
}

func validRemoteTargetTestSegment() SealedSegment {
	content := []byte("sealed segment")
	segment, err := newSealedSegment(
		ProducerId{1},
		42,
		SegmentHash(hashJournalBytes(journalSegmentHashDomain, content)),
		int64(len(content)),
		bytes.NewReader(content),
	)
	if err != nil {
		panic(err)
	}
	return segment
}
