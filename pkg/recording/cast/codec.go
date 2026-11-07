package cast

import (
	recordingid "github.com/engity-com/bifroest/pkg/recording/id"
	"time"
)

type Id = recordingid.Id

func validateId(value Id) error { return recordingid.Validate(value) }

const (
	MaximumEventElapsed         = 10 * 365 * 24 * time.Hour
	maximumEventElapsed         = MaximumEventElapsed
	MetadataSchema              = castMetadataSchema
	EventMetadataSchema         = castEventMetadataSchema
	ResultSchema                = castResultSchema
	ContentHashDomain           = castContentHashDomain
	MetadataCommentPrefix       = castMetadataCommentPrefix
	EventCommentPrefix          = castEventCommentPrefix
	ResultCommentPrefix         = castResultCommentPrefix
	SignatureCommentPrefix      = castSignatureCommentPrefix
	MaximumOutputEventLineBytes = maximumCastOutputEventLineBytes
	MaximumSealGroupBytes       = maximumCastSealGroupBytes
)

type MetadataWire = castMetadataWire
type EventMetadata = castEventMetadata
type ResultWire = castResultWire

// These shared codecs/validators are used by both native writers and portable
// verifiers. They do not imply signature trust or publish provisional output.
func EffectiveMaximumBytes(value int64) int64 { return effectiveMaximumCastBytes(value) }
func ValidateHeader(value CastHeader) error   { return validateCastHeader(value) }
func ValidateMetadata(header CastHeader, value CastMetadata) error {
	return validateCastMetadata(header, value)
}
func ValidateResult(metadata CastMetadata, value CastResult, hasExitStatus bool) error {
	return validateCastResult(metadata, value, hasExitStatus)
}
func ParseExitStatus(value string) (uint32, error)          { return parseExitStatus(value) }
func DecodeHeader(payload []byte, target *CastHeader) error { return decodeCastHeader(payload, target) }
func DecodeEvent(payload []byte) (time.Duration, string, string, error) {
	return decodeCastEvent(payload)
}
func MarshalEventString(value string) []byte { return marshalCastEventString(value) }

func ValidateResizeEvent(value string) error         { return validateResizeEvent(value) }
func RejectDuplicateJSONFields(payload []byte) error { return rejectDuplicateJSONFields(payload) }
