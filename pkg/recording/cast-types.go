package recording

import (
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

// Preserve the native recording API and exact metadata field types/codecs while
// sharing their sole implementation with the portable verifier.
const (
	CastVersion                     = cast.CastVersion
	castVersion                     = CastVersion
	castMetadataSchema              = cast.MetadataSchema
	castEventMetadataSchema         = cast.EventMetadataSchema
	castResultSchema                = cast.ResultSchema
	castContentHashDomain           = cast.ContentHashDomain
	castMetadataCommentPrefix       = cast.MetadataCommentPrefix
	castEventCommentPrefix          = cast.EventCommentPrefix
	castResultCommentPrefix         = cast.ResultCommentPrefix
	castSignatureCommentPrefix      = cast.SignatureCommentPrefix
	MaximumCastLineBytes            = cast.MaximumCastLineBytes
	MaximumOutputEventBytes         = cast.MaximumOutputEventBytes
	DefaultMaximumCastBytes         = cast.DefaultMaximumCastBytes
	maximumCastOutputEventLineBytes = cast.MaximumOutputEventLineBytes
	maximumCastSealGroupBytes       = cast.MaximumSealGroupBytes
	MaximumCastTerminalDimension    = cast.MaximumCastTerminalDimension
	MaximumCastExitStatus           = cast.MaximumCastExitStatus
	maximumEventElapsed             = cast.MaximumEventElapsed
	CastStatusCompleted             = cast.CastStatusCompleted
	CastStatusFailed                = cast.CastStatusFailed
	CastStatusIncomplete            = cast.CastStatusIncomplete
	OutputStreamTerminal            = cast.OutputStreamTerminal
	OutputStreamStdout              = cast.OutputStreamStdout
	OutputStreamStderr              = cast.OutputStreamStderr
)

type CastTerminal = cast.CastTerminal
type CastHeader = cast.CastHeader
type CastMetadata = cast.CastMetadata
type CastStatus = cast.CastStatus
type CastResult = cast.CastResult
type OutputStream = cast.OutputStream
type CastDigest = cast.CastDigest
type castResultWire = cast.ResultWire

func effectiveMaximumCastBytes(value int64) int64 { return cast.EffectiveMaximumBytes(value) }
func validateCastHeader(header CastHeader) error  { return cast.ValidateHeader(header) }
func validateCastMetadata(header CastHeader, metadata CastMetadata) error {
	return cast.ValidateMetadata(header, metadata)
}
func validateCastResult(metadata CastMetadata, result CastResult, hasExitStatus bool) error {
	return cast.ValidateResult(metadata, result, hasExitStatus)
}
func parseExitStatus(value string) (uint32, error) { return cast.ParseExitStatus(value) }

type recordingWriterLimits struct{ maximumContainerBytes, maximumCastBytes, maximumChunks uint64 }

func newRecordingWriterLimits(maximumContainerBytes, maximumCastBytes int64, maximumChunks uint64, defaultMaximumContainerBytes int64, defaultMaximumChunks uint64) (recordingWriterLimits, error) {
	if maximumContainerBytes == 0 {
		maximumContainerBytes = defaultMaximumContainerBytes
	}
	if maximumContainerBytes < 1 {
		return recordingWriterLimits{}, errors.Config.Newf("maximum Recording container size must be positive")
	}
	maximumCastBytes = effectiveMaximumCastBytes(maximumCastBytes)
	if maximumCastBytes < 1 {
		return recordingWriterLimits{}, errors.Config.Newf("maximum Cast size must be positive")
	}
	if maximumChunks == 0 {
		maximumChunks = defaultMaximumChunks
	}
	return recordingWriterLimits{uint64(maximumContainerBytes), uint64(maximumCastBytes), maximumChunks}, nil
}
func recordingCountExceedsLimit(current, increment, reserve, maximum uint64) bool {
	return current > maximum || increment > maximum-current || reserve > maximum-current-increment
}
