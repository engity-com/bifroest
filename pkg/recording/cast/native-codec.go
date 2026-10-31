package cast

import (
	"crypto/ed25519"
	"hash"
	"io"
	"time"
)

const (
	NativeRecordingHeaderDomain    = nativeRecordingHeaderDomain
	NativeRecordingChunkDomain     = nativeRecordingChunkDomain
	NativeRecordingSealDomain      = nativeRecordingSealDomain
	NativeRecordingHeadDomain      = nativeRecordingHeadDomain
	NativeRecordingUnitDomain      = nativeRecordingUnitDomain
	NativeRecordingContentDomain   = nativeRecordingContentDomain
	NativeRecordingAgePrefix       = nativeRecordingAgePrefix
	CheckpointPaddingCommentPrefix = castCheckpointPaddingCommentPrefix
)

type Sha256Checkpoint = castSha256Checkpoint

func PadForSha256Checkpoint(writer *CastWriter) (Sha256Checkpoint, error) {
	return padCastForSha256Checkpoint(writer)
}
func CheckpointSha256(h hash.Hash) (Sha256Checkpoint, error) { return checkpointCastSha256(h) }
func ResumeSha256(v Sha256Checkpoint) (hash.Hash, error)     { return resumeCastSha256(v) }
func Sha256ProcessedBytes(h hash.Hash) (uint64, error)       { return castSha256ProcessedBytes(h) }
func MarshalSha256(h hash.Hash) ([]byte, uint64, error)      { return marshalCastSha256(h) }
func (w *CastWriter) ValidateOutputStream(stream OutputStream) error {
	return w.validateOutputStream(stream)
}
func (w *CastWriter) ValidateElapsed(elapsed time.Duration) error { return w.validateElapsed(elapsed) }
func (w *CastWriter) LastElapsed() time.Duration                  { return w.lastElapsed }

func NativeRecordingRecipientValid(v string) bool { return nativeRecordingRecipientValid(v) }
func NativeRecordingHeaderFields(v NativeRecordingHeader) map[uint64]any {
	return nativeRecordingHeaderFields(v)
}
func NativeRecordingChunkFields(v NativeRecordingChunk) map[uint64]any {
	return nativeRecordingChunkFields(v)
}
func NativeRecordingSealFields(v NativeRecordingSeal) map[uint64]any {
	return nativeRecordingSealFields(v)
}
func NativeRecordingHeadFields(v NativeRecordingHead) map[uint64]any {
	return nativeRecordingHeadFields(v)
}
func NativeRecordingHash(domain string, data []byte) [32]byte {
	return nativeRecordingHash(domain, data)
}
func NativeRecordingVerify(key ed25519.PublicKey, domain string, fields map[uint64]any, signature []byte, maximum int) error {
	return nativeRecordingVerify(key, domain, fields, signature, maximum)
}
func VerifyNativeRecordingHeader(payload []byte) (NativeRecordingHeader, ed25519.PublicKey, error) {
	return verifyNativeRecordingHeader(payload)
}
func ValidateNativeRecordingSeal(seal NativeRecordingSeal, header NativeRecordingHeader) error {
	return validateNativeRecordingSeal(seal, header)
}
func CastStatusFromNativeRecording(value uint8) (CastStatus, error) {
	return castStatusFromNativeRecording(value)
}
func HashNativeRecordingUnit(r io.ReaderAt, start, end int64) ([32]byte, error) {
	return hashNativeRecordingUnit(r, start, end)
}
func HashNativeRecordingContent(r io.ReaderAt, end int64) ([32]byte, error) {
	return hashNativeRecordingContent(r, end)
}
func DecodeNativeRecordingEvents(data []byte) ([]NativeCastEvent, error) {
	return decodeNativeRecordingEvents(data)
}

func OutputChunkEnd(data []byte, offset int) int { return castOutputChunkEnd(data, offset) }
func NativeStatusNumber(value CastStatus) uint8  { return nativeStatusNumber(value) }

// ProvisionalNativeRenderer is an incremental codec, NOT full evidence
// verification or a publication boundary. Prefer VerifyNativeRecordingFull /
// ExportNativeRecordingCast for untrusted input; callers must authenticate the
// outer input/header/seal and keep all incremental output provisional.
type ProvisionalNativeRenderer = nativeCastRenderer

func NewProvisionalNativeRenderer(output io.Writer, header NativeRecordingHeader, seal NativeRecordingSeal, maximum int64) (*ProvisionalNativeRenderer, error) {
	return newNativeCastRenderer(output, header, seal, maximum)
}
func (r *nativeCastRenderer) ConsumeGroup(events []NativeCastEvent) error {
	return r.consumeGroup(events)
}
func (r *nativeCastRenderer) Finish() error { return r.finish() }
