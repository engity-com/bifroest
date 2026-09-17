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
	prefix := make([]byte, min(size, int64(len(castBECastFileMagic))))
	if _, err := source.ReadAt(prefix, 0); err != nil {
		return nil, errors.System.Newf("cannot identify Recording format: %w", err)
	}
	common := CastVerifyOptions{
		Context:            options.Context,
		MaximumBytes:       options.MaximumCastBytes,
		ExpectedProducerId: options.ExpectedProducerId,
		AllowUntrusted:     options.AllowUntrusted,
	}
	if prefix[0] == '{' {
		cast, err := VerifyCast(io.NewSectionReader(source, 0, size), common)
		if err != nil {
			return nil, err
		}
		return &Inspection{Format: FormatCast, Cast: cast}, nil
	}
	if bytes.Equal(prefix, []byte(castBECastFileMagic)) {
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
	}
	if len(prefix) >= 4 && binary.LittleEndian.Uint32(prefix[:4]) == zstdSkippableMagicBase|uint32(castZstdHeaderSkippableId) {
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
	}
	return nil, errors.Config.Newf("unsupported Recording format")
}
