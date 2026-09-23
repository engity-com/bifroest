package nativeformat

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	maxNativeZstdWindow = 2 << 20
	maxNativeZstdBlocks = 32
)

type PayloadLimits struct {
	MaxDecoded int
	MaxStored  int
}

type nativeZstdCodec struct {
	encoder *zstd.Encoder
	decoder *zstd.Decoder
	err     error
}

var sharedZstdCodec = sync.OnceValue(func() nativeZstdCodec {
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(maxNativeZstdWindow),
		zstd.WithSingleSegment(true),
	)
	if err != nil {
		return nativeZstdCodec{err: err}
	}
	decoder, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(maxNativeZstdWindow),
		zstd.WithDecoderMaxMemory(uint64(MaxRecordingDecodedChunk+maxNativeZstdWindow)),
		zstd.WithDecodeAllCapLimit(true),
	)
	if err != nil {
		encoder.Close()
		return nativeZstdCodec{err: err}
	}
	return nativeZstdCodec{encoder: encoder, decoder: decoder}
})

func (this PayloadLimits) validate() error {
	if this.MaxDecoded < 1 || this.MaxDecoded > MaxRecordingDecodedChunk || this.MaxStored < 1 || this.MaxStored > MaxRecordingChunkPayload {
		return fmt.Errorf("invalid native payload limits")
	}
	return nil
}

// EncodeZstdFrame encodes one independently decodable, checksum-protected frame.
// Incompressible input may use Zstd raw blocks, not a second wire codec.
func EncodeZstdFrame(plaintext []byte, limits PayloadLimits) ([]byte, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > limits.MaxDecoded {
		return nil, fmt.Errorf("native payload exceeds decoded limit %d", limits.MaxDecoded)
	}
	codec := sharedZstdCodec()
	if codec.err != nil {
		return nil, fmt.Errorf("cannot initialize native Zstd codec: %w", codec.err)
	}
	frame := codec.encoder.EncodeAll(plaintext, nil)
	if len(frame) == 0 || len(frame) > limits.MaxStored {
		return nil, fmt.Errorf("native Zstd frame exceeds stored limit %d", limits.MaxStored)
	}
	return frame, nil
}

func DecodeZstdFrame(frame []byte, limits PayloadLimits) ([]byte, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if len(frame) == 0 || len(frame) > limits.MaxStored {
		return nil, fmt.Errorf("native Zstd frame exceeds stored limit %d", limits.MaxStored)
	}
	length, err := scanNativeZstdFrameLength(frame)
	if err != nil {
		return nil, err
	}
	if length != len(frame) {
		return nil, fmt.Errorf("native Zstd frame contains trailing data")
	}
	var header zstd.Header
	if err := header.Decode(frame); err != nil {
		return nil, fmt.Errorf("cannot decode native Zstd header: %w", err)
	}
	if header.Skippable || !header.HasCheckSum || !header.HasFCS || header.DictionaryID != 0 || header.FrameContentSize == 0 || header.FrameContentSize > uint64(limits.MaxDecoded) {
		return nil, fmt.Errorf("native Zstd frame has invalid header metadata")
	}
	if !header.SingleSegment && (header.WindowSize == 0 || header.WindowSize > maxNativeZstdWindow) {
		return nil, fmt.Errorf("native Zstd frame has an oversized window")
	}
	codec := sharedZstdCodec()
	if codec.err != nil {
		return nil, fmt.Errorf("cannot initialize native Zstd codec: %w", codec.err)
	}
	plaintext, err := codec.decoder.DecodeAll(frame, make([]byte, 0, int(header.FrameContentSize)))
	if err != nil {
		return nil, fmt.Errorf("cannot decompress native Zstd frame: %w", err)
	}
	if len(plaintext) != int(header.FrameContentSize) {
		return nil, fmt.Errorf("native Zstd frame decoded length does not match its header")
	}
	return plaintext, nil
}

func scanNativeZstdFrameLength(frame []byte) (int, error) {
	if len(frame) < 5 || binary.LittleEndian.Uint32(frame) != 0xfd2fb528 {
		return 0, fmt.Errorf("native Zstd frame magic is invalid")
	}
	descriptor := frame[4]
	if descriptor&0x18 != 0 || descriptor&0x03 != 0 {
		return 0, fmt.Errorf("native Zstd frame has unsupported flags or dictionary")
	}
	singleSegment := descriptor&0x20 != 0
	contentSizeBytes := [...]int{0, 2, 4, 8}[descriptor>>6]
	if singleSegment && descriptor>>6 == 0 {
		contentSizeBytes = 1
	}
	offset := 5 + contentSizeBytes
	if !singleSegment {
		offset++
	}
	if offset > len(frame) {
		return 0, io.ErrUnexpectedEOF
	}
	for blocks := 0; ; blocks++ {
		if blocks >= maxNativeZstdBlocks {
			return 0, fmt.Errorf("native Zstd frame contains too many blocks")
		}
		if len(frame)-offset < 3 {
			return 0, io.ErrUnexpectedEOF
		}
		blockHeader := uint32(frame[offset]) | uint32(frame[offset+1])<<8 | uint32(frame[offset+2])<<16
		offset += 3
		blockType := blockHeader >> 1 & 3
		if blockType == 3 {
			return 0, fmt.Errorf("native Zstd frame contains a reserved block type")
		}
		physicalSize := int(blockHeader >> 3)
		if blockType == 1 {
			physicalSize = 1
		}
		if physicalSize > len(frame)-offset {
			return 0, io.ErrUnexpectedEOF
		}
		offset += physicalSize
		if blockHeader&1 != 0 {
			break
		}
	}
	if descriptor&0x04 != 0 {
		if len(frame)-offset < 4 {
			return 0, io.ErrUnexpectedEOF
		}
		offset += 4
	}
	return offset, nil
}
