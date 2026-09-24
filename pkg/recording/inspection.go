package recording

import (
	"bytes"
	"context"
	"io"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

type Format string

const (
	FormatCast       Format = "cast/v3"
	FormatBcast      Format = "bcast/v1"
	FormatBECastCBOR Format = "becast-cbor/v1"
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
	Format Format
	Cast   *CastVerification
	Native *NativeRecordingVerification
}

// Inspect verifies one Recording artifact and identifies its format.
// Encrypted native content is not decrypted; only its signed outer container
// is inspected. Clear native content is fully verified.
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
	case FormatBcast, FormatBECastCBOR:
		nativeOptions := NativeRecordingVerifyOptions{
			Context: options.Context, MaximumContainerBytes: options.MaximumContainerBytes,
			MaximumCastBytes: options.MaximumCastBytes, MaximumChunks: options.MaximumChunks,
			ExpectedProducerId: options.ExpectedProducerId, AllowUntrusted: options.AllowUntrusted,
		}
		var native *NativeRecordingVerification
		if format == FormatBcast {
			native, err = VerifyNativeRecordingFull(source, size, nil, nativeOptions)
		} else {
			native, err = VerifyNativeRecordingOuter(source, size, nativeOptions)
		}
		if err != nil {
			return nil, err
		}
		if (native.Header.Encryption == 1) != (format == FormatBECastCBOR) {
			return nil, errors.Config.Newf("native Recording format does not match encryption mode")
		}
		return &Inspection{Format: format, Native: native}, nil
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
	prefix := make([]byte, min(size, int64(len(nativeformat.RecordingMagic))))
	if _, err := source.ReadAt(prefix, 0); err != nil {
		return "", errors.System.Newf("cannot identify Recording format: %w", err)
	}
	switch {
	case len(prefix) >= len(nativeformat.RecordingMagic) && bytes.Equal(prefix[:len(nativeformat.RecordingMagic)], []byte(nativeformat.RecordingMagic)):
		unit, _, tail, err := nativeformat.ReadUnitAt(source, int64(len(nativeformat.RecordingMagic)), size, nativeformat.MaxMetadataPayload)
		if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
			return "", errors.Config.Newf("invalid native Recording header: %v", err)
		}
		header, _, err := verifyNativeRecordingHeader(unit.Payload)
		if err != nil {
			return "", err
		}
		if header.Encryption == 1 {
			return FormatBECastCBOR, nil
		}
		return FormatBcast, nil
	case prefix[0] == '{':
		return FormatCast, nil
	default:
		return "", errors.Config.Newf("unsupported Recording format")
	}
}
