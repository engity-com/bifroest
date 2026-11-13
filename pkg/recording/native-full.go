package recording

import (
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"io"
)

// VerifyNativeRecordingFull uses the shared portable outer/chunk/decryption/Cast
// verification on the same immutable ReaderAt snapshot for every pass.
func VerifyNativeRecordingFull(r io.ReaderAt, size int64, keys *bfcrypto.AgeSshIdentities, opts NativeRecordingVerifyOptions) (*NativeRecordingVerification, error) {
	return cast.VerifyNativeRecordingFull(r, size, keys, opts)
}
// ExportNativeRecordingCast emits nothing before complete verification. Export
// rereads the same immutable input; callers own atomic staging/publication if an
// output writer fails after verified export has started.
func ExportNativeRecordingCast(r io.ReaderAt, size int64, keys *bfcrypto.AgeSshIdentities, output io.Writer, opts NativeRecordingVerifyOptions) (*NativeRecordingVerification, error) {
	return cast.ExportNativeRecordingCast(r, size, keys, output, opts)
}
