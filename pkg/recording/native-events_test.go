package recording

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeCastRendererMatchesCastWriter(t *testing.T) {
	for _, pty := range []bool{true, false} {
		t.Run(map[bool]string{true: "terminal", false: "streams"}[pty], func(t *testing.T) {
			identity, header, metadata := castTestValues(t, pty)
			var expected bytes.Buffer
			writer, err := NewCastWriter(&expected, identity, header, metadata)
			require.NoError(t, err)
			events := []NativeCastEvent{{Kind: NativeEventSetup, Header: header, Metadata: metadata}}
			stream := OutputStreamTerminal
			if !pty {
				stream = OutputStreamStdout
			}
			data := []byte("hello \xe2\x98\x83\n\x00")
			events = append(events, NativeCastEvent{Kind: NativeEventOutput, Elapsed: 123456789 * time.Nanosecond, Stream: stream, Data: data})
			require.NoError(t, writer.WriteOutput(123456789*time.Nanosecond, stream, data))
			if pty {
				events = append(events, NativeCastEvent{Kind: NativeEventResize, Elapsed: 150 * time.Millisecond, Columns: 99, Rows: 22})
				require.NoError(t, writer.WriteResize(150*time.Millisecond, 99, 22))
			} else {
				binary := []byte{0xff, 'a', 0xfe}
				events = append(events, NativeCastEvent{Kind: NativeEventOutput, Elapsed: 150 * time.Millisecond, Stream: OutputStreamStderr, Data: binary})
				require.NoError(t, writer.WriteOutput(150*time.Millisecond, OutputStreamStderr, binary))
			}
			events = append(events, NativeCastEvent{Kind: NativeEventMarker, Elapsed: 155 * time.Millisecond, Label: "ready\u2028"})
			require.NoError(t, writer.WriteMarker(155*time.Millisecond, "ready\u2028"))
			events = append(events, NativeCastEvent{Kind: NativeEventPaddingCheckpoint})
			_, err = padCastForSha256Checkpoint(writer)
			require.NoError(t, err)
			first, err := EncodeNativeRecordingEvents(events)
			require.NoError(t, err)
			result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}
			exit := uint32(9)
			second, err := EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventResult, Elapsed: time.Second, Result: result, ExitStatus: &exit}})
			require.NoError(t, err)
			digest, err := writer.Seal(time.Second, result, &exit)
			require.NoError(t, err)
			sig, err := identity.NewSessionRecordingCastSignature(metadata.RecordingId.String(), digest.String())
			require.NoError(t, err)
			signedHeader := NativeRecordingHeader{Version: 1, RecordingId: [16]byte(metadata.RecordingId), ProducerId: [32]byte(metadata.ProducerId), PublicKey: identity.PublicKey().Marshal(), StartedAt: nativeformat.TimestampOf(metadata.StartedAt)}
			seal := NativeRecordingSeal{Status: 1, ChunkCount: 2, CastDigest: [32]byte(digest), CastSignature: sig.Signature, CastBytes: uint64(expected.Len()), EndedAt: nativeformat.TimestampOf(result.EndedAt)}
			actual, err := RenderNativeRecordingCast([][]byte{first, second}, signedHeader, seal, int64(expected.Len()))
			require.NoError(t, err)
			require.Equal(t, expected.Bytes(), actual)
			for _, tc := range []struct {
				name   string
				index  int
				events []NativeCastEvent
			}{
				{"nonfinal without padding", 0, events[:len(events)-1]},
				{"nonfinal misplaced padding", 0, append(append([]NativeCastEvent(nil), events[:len(events)-2]...), events[len(events)-1], events[len(events)-2])},
				{"nonfinal duplicate padding", 0, append(append([]NativeCastEvent(nil), events...), NativeCastEvent{Kind: NativeEventPaddingCheckpoint})},
				{"final leading padding", 1, []NativeCastEvent{{Kind: NativeEventPaddingCheckpoint}, {Kind: NativeEventResult, Elapsed: time.Second, Result: result, ExitStatus: &exit}}},
				{"final trailing padding", 1, []NativeCastEvent{{Kind: NativeEventResult, Elapsed: time.Second, Result: result, ExitStatus: &exit}, {Kind: NativeEventPaddingCheckpoint}}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					bad, err := EncodeNativeRecordingEvents(tc.events)
					require.NoError(t, err)
					groups := [][]byte{first, second}
					groups[tc.index] = bad
					actual, err := RenderNativeRecordingCast(groups, signedHeader, seal, int64(expected.Len()))
					require.ErrorContains(t, err, "invalid padding checkpoint")
					require.Nil(t, actual)
					if tc.index == 0 {
						var output bytes.Buffer
						renderer, err := newNativeCastRenderer(&output, signedHeader, seal, int64(expected.Len()))
						require.NoError(t, err)
						decoded, err := decodeNativeRecordingEvents(bad)
						require.NoError(t, err)
						require.ErrorContains(t, renderer.consumeGroup(decoded), "invalid padding checkpoint")
						require.Zero(t, output.Len())
					}
				})
			}
			for _, invalid := range [][]NativeCastEvent{
				{events[1], events[0]},
				{events[0], events[0]},
				{events[0], {Kind: NativeEventOutput, Elapsed: time.Millisecond, Stream: stream, Data: []byte("ok")}, {Kind: NativeEventMarker, Label: "backwards"}},
				{events[0], {Kind: NativeEventMarker, Label: string(bytes.Repeat([]byte("x"), 4097))}},
			} {
				bad, err := EncodeNativeRecordingEvents(invalid)
				if err == nil {
					actual, err = RenderNativeRecordingCast([][]byte{bad, second}, signedHeader, seal, int64(expected.Len()))
					require.Error(t, err)
					require.Nil(t, actual)
				}
			}
			actual, err = RenderNativeRecordingCast([][]byte{first}, signedHeader, seal, int64(expected.Len()))
			require.Error(t, err)
			require.Nil(t, actual)
			seal.CastBytes--
			actual, err = RenderNativeRecordingCast([][]byte{first, second}, signedHeader, seal, int64(expected.Len()))
			require.Error(t, err)
			require.Nil(t, actual)
			seal.CastBytes++
			seal.CastDigest[0] ^= 1
			actual, err = RenderNativeRecordingCast([][]byte{first, second}, signedHeader, seal, int64(expected.Len()))
			require.Error(t, err)
			require.Nil(t, actual)
		})
	}
}

func TestNativeEventRejectsInvalidOrderingAndShape(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	setup := NativeCastEvent{Kind: NativeEventSetup, Header: header, Metadata: metadata}
	output := NativeCastEvent{Kind: NativeEventOutput, Elapsed: time.Millisecond, Stream: OutputStreamTerminal, Data: []byte("ok")}
	_, err := EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventOutput, Data: bytes.Repeat([]byte("x"), MaximumOutputEventBytes+1), Stream: OutputStreamTerminal}})
	require.Error(t, err)
	_, err = EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventOutput, Stream: OutputStreamTerminal}})
	require.Error(t, err)
	good, err := EncodeNativeRecordingEvents([]NativeCastEvent{setup, output})
	require.NoError(t, err)
	var cast bytes.Buffer
	writer, err := NewCastWriter(&cast, identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("ok")))
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}
	exit := uint32(0)
	digest, err := writer.Seal(time.Second, result, &exit)
	require.NoError(t, err)
	signature, err := identity.NewSessionRecordingCastSignature(metadata.RecordingId.String(), digest.String())
	require.NoError(t, err)
	final, err := EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventResult, Elapsed: time.Second, Result: result, ExitStatus: &exit}})
	require.NoError(t, err)
	signedHeader := NativeRecordingHeader{Version: 1, RecordingId: [16]byte(metadata.RecordingId), ProducerId: [32]byte(metadata.ProducerId), PublicKey: identity.PublicKey().Marshal(), StartedAt: nativeformat.TimestampOf(metadata.StartedAt)}
	seal := NativeRecordingSeal{Status: 1, ChunkCount: 2, CastDigest: [32]byte(digest), CastSignature: signature.Signature, CastBytes: uint64(cast.Len()), EndedAt: nativeformat.TimestampOf(result.EndedAt)}
	_, err = RenderNativeRecordingCast([][]byte{good}, signedHeader, seal, 100000)
	require.Error(t, err)
	for _, invalid := range [][]NativeCastEvent{
		{output, setup},
		{setup, setup},
		{setup, {Kind: NativeEventMarker, Label: string(bytes.Repeat([]byte("x"), 4097))}},
		{setup, output, {Kind: NativeEventOutput, Elapsed: 0, Stream: OutputStreamTerminal, Data: []byte("backwards")}},
		{setup, {Kind: NativeEventResize, Elapsed: time.Second, Columns: 0, Rows: 1}},
	} {
		bad, encodeErr := EncodeNativeRecordingEvents(invalid)
		if encodeErr == nil {
			actual, renderErr := RenderNativeRecordingCast([][]byte{bad, final}, signedHeader, seal, 100000)
			require.Error(t, renderErr)
			require.Nil(t, actual)
		}
	}
	_, err = EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventSetup, Header: CastHeader{Version: 3, Terminal: CastTerminal{Columns: 1, Rows: 1, Type: string(bytes.Repeat([]byte("x"), 256))}, Timestamp: header.Timestamp}, Metadata: metadata}})
	require.Error(t, err)
	malformed, err := nativeformat.Marshal(map[uint64]any{1: uint64(1), 2: []any{map[uint64]any{1: uint64(NativeEventPaddingCheckpoint), 77: uint64(2)}}}, nativeformat.MaxRecordingDecodedChunk)
	require.NoError(t, err)
	_, err = decodeNativeRecordingEvents(malformed)
	require.Error(t, err)
	_, err = EncodeNativeRecordingEvents([]NativeCastEvent{setup, {Kind: NativeEventResult, Elapsed: -time.Second}})
	require.Error(t, err)
}

func TestNativeCastRendererPreservesUTF8OutputSplit(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var expected bytes.Buffer
	writer, err := NewCastWriter(&expected, identity, header, metadata)
	require.NoError(t, err)
	data := append(bytes.Repeat([]byte("x"), MaximumOutputEventBytes-1), []byte("\xe2\x98\x83tail\xff")...)
	require.NoError(t, writer.WriteOutput(321*time.Millisecond, OutputStreamTerminal, data))
	events := []NativeCastEvent{{Kind: NativeEventSetup, Header: header, Metadata: metadata}}
	for offset := 0; offset < len(data); {
		end := castOutputChunkEnd(data, offset)
		events = append(events, NativeCastEvent{Kind: NativeEventOutput, Elapsed: 321 * time.Millisecond, Stream: OutputStreamTerminal, Data: data[offset:end]})
		offset = end
	}
	events = append(events, NativeCastEvent{Kind: NativeEventPaddingCheckpoint})
	_, err = padCastForSha256Checkpoint(writer)
	require.NoError(t, err)
	group, err := EncodeNativeRecordingEvents(events)
	require.NoError(t, err)
	result := CastResult{Status: CastStatusFailed, EndedAt: metadata.StartedAt.Add(time.Second), Reason: "failed"}
	final, err := EncodeNativeRecordingEvents([]NativeCastEvent{{Kind: NativeEventResult, Elapsed: time.Second, Result: result}})
	require.NoError(t, err)
	digest, err := writer.Seal(time.Second, result, nil)
	require.NoError(t, err)
	sig, err := identity.NewSessionRecordingCastSignature(metadata.RecordingId.String(), digest.String())
	require.NoError(t, err)
	signedHeader := NativeRecordingHeader{Version: 1, RecordingId: [16]byte(metadata.RecordingId), ProducerId: [32]byte(metadata.ProducerId), PublicKey: identity.PublicKey().Marshal(), StartedAt: nativeformat.TimestampOf(metadata.StartedAt)}
	seal := NativeRecordingSeal{Status: 2, ChunkCount: 2, CastDigest: [32]byte(digest), CastSignature: sig.Signature, CastBytes: uint64(expected.Len()), EndedAt: nativeformat.TimestampOf(result.EndedAt)}
	actual, err := RenderNativeRecordingCast([][]byte{group, final}, signedHeader, seal, int64(expected.Len()))
	require.NoError(t, err)
	require.Equal(t, expected.Bytes(), actual)
}
