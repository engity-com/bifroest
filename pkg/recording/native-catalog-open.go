package recording

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"os"

	"github.com/engity-com/bifroest/pkg/recording/cast"
)

var ErrCatalogVerificationBudget = stderrors.New("recording catalog exceeds bounded verification budget")

// CatalogVerifyLimits is a mandatory per-call allowance, not a repository or
// signing-format setting. Zero never means fallback to the large CLI defaults.
type CatalogVerifyLimits struct {
	MaximumContainerBytes uint64
	MaximumCastBytes      uint64
}

func (limits CatalogVerifyLimits) validate() error {
	if limits.MaximumContainerBytes == 0 || limits.MaximumContainerBytes > MaximumNativeCatalogBytes ||
		limits.MaximumCastBytes == 0 || limits.MaximumCastBytes > MaximumNativeCatalogBytes {
		return fmt.Errorf("%w: invalid per-call limits", ErrCatalogVerificationBudget)
	}
	return nil
}

// LocalCatalogSealedArtifact records the larger of canonical Cast bytes and
// decoded CBOR bytes per verification pass. Native full verification has a fixed
// outer/inner pass count; each pass is individually bounded by the same allowance.
// No plaintext/metadata beyond the ordinary verified summary is added here.
type LocalCatalogSealedArtifact struct {
	*LocalSealedArtifact[NativeRecordingSummary]
	verificationCastBytes uint64
}

func (artifact *LocalCatalogSealedArtifact) VerificationCastBytes() uint64 {
	return artifact.verificationCastBytes
}

// OpenCatalogSealed always reopens and reverifies the current artifact with this
// call's remaining budgets. It never trusts cached sizes, changes repository
// defaults, accepts private keys, or reuses a cached verification as authority.
func (r *LocalNativeRecordingRepository) OpenCatalogSealed(ctx context.Context, id Id, limits CatalogVerifyLimits) (*LocalCatalogSealedArtifact, error) {
	if r == nil || r.repository == nil {
		return nil, fmt.Errorf("nil recording catalog")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	var castVerificationBytes uint64
	artifact, err := r.repository.openSealedWithVerifier(ctx, id, func(file *os.File, size int64, ctx context.Context) (NativeRecordingSummary, error) {
		summary, used, err := r.verifyCatalogFile(ctx, file, size, limits)
		castVerificationBytes = used
		return summary, err
	})
	if err != nil {
		return nil, err
	}
	return &LocalCatalogSealedArtifact{LocalSealedArtifact: artifact, verificationCastBytes: castVerificationBytes}, nil
}

func (r *LocalNativeRecordingRepository) verifyCatalogFile(ctx context.Context, source io.ReaderAt, size int64, limits CatalogVerifyLimits) (NativeRecordingSummary, uint64, error) {
	if err := limits.validate(); err != nil {
		return NativeRecordingSummary{}, 0, err
	}
	// This gate uses fstat on the actual open descriptor, before even magic,
	// header, hash or compressed payload reads. The caller supplies that stat.
	if size < 1 || uint64(size) > limits.MaximumContainerBytes {
		return NativeRecordingSummary{}, 0, fmt.Errorf("%w: actual container size", ErrCatalogVerificationBudget)
	}
	catalogReadWork(ctx, true)
	format, ok := r.repository.format.(*localNativeRecordingFormat)
	if !ok {
		return NativeRecordingSummary{}, 0, fmt.Errorf("recording catalog requires native format")
	}
	options := format.options // Per-call copy; never mutate shared repo options.
	if options.MaximumContainerBytes == 0 {
		options.MaximumContainerBytes = DefaultMaximumNativeRecordingBytes
	}
	if options.MaximumCastBytes == 0 {
		options.MaximumCastBytes = DefaultMaximumCastBytes
	}
	options.MaximumContainerBytes = min(options.MaximumContainerBytes, int64(limits.MaximumContainerBytes))
	options.MaximumCastBytes = min(options.MaximumCastBytes, int64(limits.MaximumCastBytes))
	options.Context = ctx
	options.ExpectedProducerId = r.repository.identity.ProducerId()
	options.AllowUntrusted = false
	var metadata *CastMetadata
	options.VerifiedMetadata = func(value CastMetadata) { metadata = &value }
	// Confine all verifier passes to the same fstat-sized descriptor view.
	reader := io.NewSectionReader(source, 0, size)
	verification, decodedBytes, err := cast.VerifyNativeRecordingCatalog(reader, size, format.recipient != nil, uint64(options.MaximumCastBytes), options)
	if err != nil {
		return NativeRecordingSummary{}, 0, err
	}
	if (verification.Header.Encryption == 1) != (format.recipient != nil) {
		return NativeRecordingSummary{}, 0, fmt.Errorf("recording catalog encryption mismatch")
	}
	status, err := castStatusFromNativeRecording(verification.Seal.Status)
	if err != nil {
		return NativeRecordingSummary{}, 0, err
	}
	castVerificationBytes := max(verification.Seal.CastBytes, decodedBytes)
	if castVerificationBytes > limits.MaximumCastBytes {
		return NativeRecordingSummary{}, 0, fmt.Errorf("%w: decoded/canonical Cast bytes", ErrCatalogVerificationBudget)
	}
	return nativeSummary(verification, status, uint64(size), metadata), castVerificationBytes, nil
}
