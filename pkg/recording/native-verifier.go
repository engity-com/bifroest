package recording

import (
	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"io"
)

type NativeRecordingVerifyOptions = cast.NativeRecordingVerifyOptions
type NativeRecordingVerification = cast.NativeRecordingVerification

const (
	nativeRecordingAgePrefix            = cast.NativeRecordingAgePrefix
	DefaultMaximumNativeRecordingBytes  = cast.DefaultMaximumNativeRecordingBytes
	DefaultMaximumNativeRecordingChunks = cast.DefaultMaximumNativeRecordingChunks
)

func effectiveMaximumNativeRecordingChunks(v uint64) uint64 {
	if v == 0 {
		return DefaultMaximumNativeRecordingChunks
	}
	return v
}
func castStatusFromNativeRecording(v uint8) (CastStatus, error) {
	return cast.CastStatusFromNativeRecording(v)
}
func validateNativeRecordingSeal(s nativeRecordingSeal, h nativeRecordingHeader) error {
	return cast.ValidateNativeRecordingSeal(s, h)
}
// VerifyNativeRecordingOuter authenticates the committed envelope, NOT full
// inner-event semantics/decryption. Its result cannot authorize plaintext export.
func VerifyNativeRecordingOuter(r io.ReaderAt, size int64, opts NativeRecordingVerifyOptions) (*NativeRecordingVerification, error) {
	return cast.VerifyNativeRecordingOuter(r, size, opts)
}
func VerifyNativeRecordingHead(payload, header []byte) (NativeRecordingHead, error) {
	return cast.VerifyNativeRecordingHead(payload, header)
}
func VerifyNativeRecordingCheckpoint(r io.ReaderAt, size int64, head []byte, identity *audit.Identity, opts NativeRecordingVerifyOptions) error {
	return cast.VerifyNativeRecordingCheckpoint(r, size, head, identity, opts)
}
func hashNativeRecordingUnit(r io.ReaderAt, start, end int64) ([32]byte, error) {
	return cast.HashNativeRecordingUnit(r, start, end)
}
func hashNativeRecordingContent(r io.ReaderAt, end int64) ([32]byte, error) {
	return cast.HashNativeRecordingContent(r, end)
}
