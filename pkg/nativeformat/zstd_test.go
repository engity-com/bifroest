package nativeformat

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

func TestNativeZstdFramesAreIndependentAndBounded(t *testing.T) {
	limits := PayloadLimits{MaxDecoded: MaxAuditEventPayload, MaxStored: MaxAuditRecordPayload}
	first := bytes.Repeat([]byte("authentication.flow.evaluated"), 20)
	second := bytes.Repeat([]byte("connection.closed"), 20)
	firstFrame, err := EncodeZstdFrame(first, limits)
	require.NoError(t, err)
	secondFrame, err := EncodeZstdFrame(second, limits)
	require.NoError(t, err)
	var header zstd.Header
	require.NoError(t, header.Decode(firstFrame))
	require.True(t, header.SingleSegment)
	require.True(t, header.HasFCS)
	require.True(t, header.HasCheckSum)
	decoded, err := DecodeZstdFrame(firstFrame, limits)
	require.NoError(t, err)
	require.Equal(t, first, decoded)
	decoded, err = DecodeZstdFrame(firstFrame, PayloadLimits{MaxDecoded: len(first), MaxStored: len(firstFrame)})
	require.NoError(t, err, "exactly sufficient encoded and decoded limits must work")
	require.Equal(t, first, decoded)
	decoded, err = DecodeZstdFrame(secondFrame, limits)
	require.NoError(t, err)
	require.Equal(t, second, decoded)

	for name, candidate := range map[string][]byte{
		"another frame": append(bytes.Clone(firstFrame), secondFrame...),
		"trailing byte": append(bytes.Clone(firstFrame), 0),
		"truncated":     firstFrame[:len(firstFrame)-1],
		"bad checksum": func() []byte {
			v := bytes.Clone(firstFrame)
			v[len(v)-1] ^= 1
			return v
		}(),
		"tampered payload": func() []byte {
			v := bytes.Clone(firstFrame)
			v[len(v)-5] ^= 1
			return v
		}(),
		"dictionary": func() []byte {
			v := bytes.Clone(firstFrame)
			v[4] |= 1
			return v
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeZstdFrame(candidate, limits)
			require.Error(t, err)
		})
	}

	_, err = DecodeZstdFrame(firstFrame, PayloadLimits{MaxDecoded: len(first) - 1, MaxStored: limits.MaxStored})
	require.Error(t, err)
	_, err = DecodeZstdFrame(firstFrame, PayloadLimits{MaxDecoded: limits.MaxDecoded, MaxStored: len(firstFrame) - 1})
	require.Error(t, err)
	_, err = EncodeZstdFrame(bytes.Repeat([]byte{'x'}, limits.MaxDecoded+1), limits)
	require.Error(t, err)
	_, err = EncodeZstdFrame(first, PayloadLimits{MaxDecoded: limits.MaxDecoded, MaxStored: 1})
	require.Error(t, err)
	_, err = EncodeZstdFrame(first, PayloadLimits{})
	require.Error(t, err)

	largeFrame, err := EncodeZstdFrame(bytes.Repeat([]byte{'z'}, 1024), limits)
	require.NoError(t, err)
	require.NoError(t, header.Decode(largeFrame))
	require.Equal(t, uint64(1024), header.FrameContentSize)
	require.Equal(t, 7, header.HeaderSize)
	forgedSize := bytes.Clone(largeFrame)
	binary.LittleEndian.PutUint16(forgedSize[5:7], 0) // A two-byte FCS of zero claims 256 decoded bytes.
	decoded, err = DecodeZstdFrame(forgedSize, PayloadLimits{MaxDecoded: 256, MaxStored: limits.MaxStored})
	require.Error(t, err, "an expansion beyond the declared frame size must fail")
	require.Nil(t, decoded)
}

func TestNativeZstdAcceptsRawBlocks(t *testing.T) {
	limits := PayloadLimits{MaxDecoded: MaxAuditEventPayload, MaxStored: MaxAuditRecordPayload}
	content := bytes.Repeat([]byte("record"), 15)
	compressed, err := EncodeZstdFrame(content, limits)
	require.NoError(t, err)
	var header zstd.Header
	require.NoError(t, header.Decode(compressed))
	require.LessOrEqual(t, len(content), 128<<10)
	rawFrame := append([]byte(nil), compressed[:header.HeaderSize]...)
	var rawBlock [3]byte
	blockHeader := uint32(len(content))<<3 | 1
	rawBlock[0], rawBlock[1], rawBlock[2] = byte(blockHeader), byte(blockHeader>>8), byte(blockHeader>>16)
	rawFrame = append(rawFrame, rawBlock[:]...)
	rawFrame = append(rawFrame, content...)
	rawFrame = append(rawFrame, compressed[len(compressed)-4:]...)
	decoded, err := DecodeZstdFrame(rawFrame, limits)
	require.NoError(t, err)
	require.Equal(t, content, decoded)
	require.Equal(t, uint32(0xfd2fb528), binary.LittleEndian.Uint32(rawFrame))
}

func TestNativeZstdDecodesMaximumRecordingChunk(t *testing.T) {
	limits := PayloadLimits{MaxDecoded: MaxRecordingDecodedChunk, MaxStored: MaxRecordingChunkPayload}
	content := make([]byte, limits.MaxDecoded)
	_, err := rand.Read(content)
	require.NoError(t, err)
	frame, err := EncodeZstdFrame(content, limits)
	require.NoError(t, err)
	decoded, err := DecodeZstdFrame(frame, limits)
	require.NoError(t, err)
	require.Equal(t, content, decoded)
	_, err = DecodeZstdFrame(frame, PayloadLimits{MaxDecoded: limits.MaxDecoded - 1, MaxStored: limits.MaxStored})
	require.Error(t, err)
}

func TestNativeZstdConcurrentUnitsStayIndependent(t *testing.T) {
	limits := PayloadLimits{MaxDecoded: MaxAuditEventPayload, MaxStored: MaxAuditRecordPayload}
	var workers sync.WaitGroup
	failures := make(chan error, 16)
	for index := range 16 {
		workers.Go(func() {
			content := bytes.Repeat([]byte{byte(index)}, 4<<10)
			for range 10 {
				frame, err := EncodeZstdFrame(content, limits)
				if err == nil {
					var decoded []byte
					decoded, err = DecodeZstdFrame(frame, limits)
					if err == nil && !bytes.Equal(decoded, content) {
						err = fmt.Errorf("Zstd output changed between concurrent units")
					}
				}
				if err != nil {
					failures <- err
					return
				}
			}
		})
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
}

func BenchmarkNativeZstdAuditEvent(b *testing.B) {
	plaintext, err := Marshal(map[uint64]any{
		1: "restricted", 2: "7f29116f-d934-492a-a2af-1e581b06c021",
		3: "authorization.flow.evaluated", 4: "password", 5: "success",
	}, MaxAuditEventPayload)
	if err != nil {
		b.Fatal(err)
	}
	limits := PayloadLimits{MaxDecoded: MaxAuditEventPayload, MaxStored: MaxAuditRecordPayload}
	frame, err := EncodeZstdFrame(plaintext, limits)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if _, err := EncodeZstdFrame(plaintext, limits); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(frame))/float64(len(plaintext)), "frame/raw")
}
