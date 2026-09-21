package recording

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

type Format string

const (
	FormatCast     Format = "cast/v3"
	FormatCastZstd Format = "cast-zstd/v1"
	FormatBECast   Format = "becast/v1"
)

type InspectOptions struct {
	Context               context.Context
	MaximumContainerBytes int64
	MaximumCastBytes      int64
	MaximumChunks         uint64
	ExpectedProducerId    audit.ProducerId
	AllowUntrusted        bool
}

type Inspection struct {
	Format   Format
	Cast     *CastVerification
	CastZstd *CastZstdVerification
	BECast   *BECastVerification
}

// Inspect verifies one Recording artifact and identifies its format.
// Encrypted BECast content is not decrypted; only its signed outer container is
// inspected.
func Inspect(source io.ReaderAt, size int64, options InspectOptions) (*Inspection, error) {
	if source == nil {
		return nil, errors.System.Newf("nil Recording inspection source")
	}
	if size < 1 {
		return nil, errors.Config.Newf("Recording inspection source is empty")
	}
	if options.Context == nil {
		options.Context = context.Background()
	}
	format, err := DetectFormat(source, size)
	if err != nil {
		return nil, err
	}
	common := CastVerifyOptions{
		Context:            options.Context,
		MaximumBytes:       options.MaximumCastBytes,
		ExpectedProducerId: options.ExpectedProducerId,
		AllowUntrusted:     options.AllowUntrusted,
	}
	switch format {
	case FormatCast:
		maximumContainerBytes := options.MaximumContainerBytes
		if maximumContainerBytes == 0 {
			maximumContainerBytes = DefaultMaximumCastBytes
		}
		if maximumContainerBytes < 1 {
			return nil, errors.Config.Newf("maximum Cast container size must be positive")
		}
		if size > maximumContainerBytes {
			return nil, errors.System.Newf("Cast container size %d is outside the supported range", size)
		}
		cast, err := VerifyCast(io.NewSectionReader(source, 0, size), common)
		if err != nil {
			return nil, err
		}
		return &Inspection{Format: FormatCast, Cast: cast}, nil
	case FormatBECast:
		becast, err := VerifyBECast(source, size, BECastVerifyOptions{
			ExpectedProducerId:    options.ExpectedProducerId,
			AllowUntrusted:        options.AllowUntrusted,
			MaximumContainerBytes: options.MaximumContainerBytes,
			MaximumCastBytes:      options.MaximumCastBytes,
			MaximumChunks:         options.MaximumChunks,
			Context:               options.Context,
		})
		if err != nil {
			return nil, err
		}
		return &Inspection{Format: FormatBECast, BECast: becast}, nil
	case FormatCastZstd:
		castZstd, err := VerifyCastZstd(source, size, CastZstdVerifyOptions{
			Context:               options.Context,
			MaximumContainerBytes: options.MaximumContainerBytes,
			MaximumCastBytes:      options.MaximumCastBytes,
			MaximumChunks:         options.MaximumChunks,
			ExpectedProducerId:    options.ExpectedProducerId,
			AllowUntrusted:        options.AllowUntrusted,
		})
		if err != nil {
			return nil, err
		}
		return &Inspection{Format: FormatCastZstd, Cast: castZstd.Cast, CastZstd: castZstd}, nil
	default:
		return nil, errors.Config.Newf("unsupported Recording format %q", format)
	}
}

// DetectFormat identifies a Recording by its content without verifying it.
func DetectFormat(source io.ReaderAt, size int64) (Format, error) {
	if source == nil {
		return "", errors.System.Newf("nil Recording format source")
	}
	if size < 1 {
		return "", errors.Config.Newf("Recording format source is empty")
	}
	prefix := make([]byte, min(size, int64(len(castBECastFileMagic))))
	if _, err := source.ReadAt(prefix, 0); err != nil {
		return "", errors.System.Newf("cannot identify Recording format: %w", err)
	}
	switch {
	case prefix[0] == '{':
		return FormatCast, nil
	case bytes.Equal(prefix, []byte(castBECastFileMagic)):
		return FormatBECast, nil
	case len(prefix) >= 4 && binary.LittleEndian.Uint32(prefix[:4]) == zstdSkippableMagicBase|uint32(castZstdHeaderSkippableId):
		return FormatCastZstd, nil
	default:
		return "", errors.Config.Newf("unsupported Recording format")
	}
}
