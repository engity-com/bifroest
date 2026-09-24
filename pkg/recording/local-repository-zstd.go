package recording

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	localCastZstdFormatKey       = "cast-zstd/v1"
	localCastZstdContentFileName = "recording.cast.zst"
	localCastZstdSealedSuffix    = ".cast.zst"
)

type LocalCastZstdRepository struct {
	repository *localRepository[audit.SessionRecordingZstdHead, CastZstdSummary]
}

type RecoveredCastZstd struct {
	Summary       CastZstdSummary
	Truncated     bool
	AlreadySealed bool
}

type ActiveCastZstd struct {
	active *localActive[audit.SessionRecordingZstdHead, CastZstdSummary]
}

type localCastZstdFormat struct {
	identity *audit.Identity
	options  CastZstdVerifyOptions
}

func (this *localCastZstdFormat) key() string {
	return localCastZstdFormatKey
}

func NewLocalCastZstdRepository(ctx context.Context, directory string, identity *audit.Identity, options CastZstdVerifyOptions, repositoryOptions LocalRepositoryOptions) (*LocalCastZstdRepository, error) {
	return NewLocalCastZstdRepositoryWithArtifactPreparer(ctx, directory, identity, options, repositoryOptions, nil)
}

func NewLocalCastZstdRepositoryWithArtifactPreparer(ctx context.Context, directory string, identity *audit.Identity, options CastZstdVerifyOptions, repositoryOptions LocalRepositoryOptions, prepareSealed SealedArtifactPreparer) (*LocalCastZstdRepository, error) {
	if identity == nil || identity.PublicKey() == nil {
		return nil, errors.Config.Newf("nil local recording identity")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	options.ExpectedProducerId = identity.ProducerId()
	options.AllowUntrusted = false
	options.Context = ctx
	format := &localCastZstdFormat{identity: identity, options: options}
	repository, err := newLocalRepository(ctx, directory, identity, format, repositoryOptions, prepareSealed)
	if err != nil {
		return nil, err
	}
	return &LocalCastZstdRepository{repository: repository}, nil
}

func (this *LocalCastZstdRepository) StartupRecoveries() []RecoveredCastZstd {
	if this == nil || this.repository == nil {
		return nil
	}
	recovered := this.repository.startupRecoveries()
	result := make([]RecoveredCastZstd, len(recovered))
	for index, current := range recovered {
		result[index] = RecoveredCastZstd{
			Summary:       current.summary,
			Truncated:     current.truncated,
			AlreadySealed: current.alreadySealed,
		}
	}
	return result
}

func (this *LocalCastZstdRepository) ListSealed(ctx context.Context) ([]Id, error) {
	if this == nil {
		return nil, errors.System.Newf("nil local Cast Zstandard repository")
	}
	return this.repository.listSealed(ctx)
}

func (this *LocalCastZstdRepository) RecordingStateExists(id Id) (bool, error) {
	if this == nil {
		return false, errors.System.Newf("nil local Cast Zstandard repository")
	}
	return this.repository.recordingStateExists(id)
}

func (this *LocalCastZstdRepository) OpenSealed(ctx context.Context, id Id) (*LocalSealedArtifact[CastZstdSummary], error) {
	if this == nil {
		return nil, errors.System.Newf("nil local Cast Zstandard repository")
	}
	return this.repository.openSealed(ctx, id)
}

func (this *LocalCastZstdRepository) DeleteSealed(ctx context.Context, id Id, expectedDigest ArtifactDigest, expectedSize int64) (bool, error) {
	if this == nil {
		return false, errors.System.Newf("nil local Cast Zstandard repository")
	}
	return this.repository.deleteSealed(ctx, id, expectedDigest, expectedSize)
}

func (this *LocalCastZstdRepository) CreateActive(ctx context.Context, header CastHeader, metadata CastMetadata, chunkSize int) (*ActiveCastZstd, error) {
	if this == nil {
		return nil, errors.System.Newf("nil local recording repository")
	}
	active, err := this.repository.createActive(ctx, header, metadata, chunkSize)
	if err != nil {
		return nil, err
	}
	return &ActiveCastZstd{active: active}, nil
}

func (this *LocalCastZstdRepository) Close() error {
	if this == nil {
		return nil
	}
	return this.repository.close(false)
}

func (this *LocalCastZstdRepository) CloseAfterAcceptedFailure() error {
	if this == nil {
		return nil
	}
	return this.repository.close(true)
}

func (this *ActiveCastZstd) WriteOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	return this.local().writeOutput(elapsed, stream, data)
}

func (this *ActiveCastZstd) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	return this.local().writeResize(elapsed, columns, rows)
}

func (this *ActiveCastZstd) WriteMarker(elapsed time.Duration, label string) error {
	return this.local().writeMarker(elapsed, label)
}

func (this *ActiveCastZstd) Checkpoint() error {
	return this.local().checkpoint()
}

func (this *ActiveCastZstd) Seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (CastZstdSummary, error) {
	return this.local().seal(elapsed, result, exitStatus)
}

func (this *ActiveCastZstd) Close() error {
	return this.local().closeAndRemove()
}

func (this *ActiveCastZstd) local() *localActive[audit.SessionRecordingZstdHead, CastZstdSummary] {
	if this == nil {
		return nil
	}
	return this.active
}

func (this *localCastZstdFormat) contentFileName() string {
	return localCastZstdContentFileName
}

func (this *localCastZstdFormat) headFileName() string { return localHeadFileName }

func (this *localCastZstdFormat) sealedSuffix() string {
	return localCastZstdSealedSuffix
}

func (this *localCastZstdFormat) maximumHeadBytes() int64 {
	return maximumCastZstdHeadBytes
}

func (this *localCastZstdFormat) newWriter(output io.Writer, header CastHeader, metadata CastMetadata, chunkSize int) (localWriter[audit.SessionRecordingZstdHead, CastZstdSummary], error) {
	return newCastZstdWriter(output, this.identity, header, metadata, chunkSize, this.options)
}

func (this *localCastZstdFormat) encodeHead(head audit.SessionRecordingZstdHead) ([]byte, error) {
	return encodeCastZstdHead(head)
}

func (this *localCastZstdFormat) decodeHead(payload []byte) (audit.SessionRecordingZstdHead, error) {
	return decodeCastZstdHead(payload)
}

func (this *localCastZstdFormat) headId(head audit.SessionRecordingZstdHead) Id {
	return Id(head.RecordingId)
}

func (this *localCastZstdFormat) headProducerId(head audit.SessionRecordingZstdHead) audit.ProducerId {
	return head.ProducerId
}

func (this *localCastZstdFormat) headPrefixBytes(head audit.SessionRecordingZstdHead) uint64 {
	return head.PrefixBytes
}

func (this *localCastZstdFormat) preflight(*os.File, int64, audit.SessionRecordingZstdHead, context.Context) error {
	return nil
}

func (this *localCastZstdFormat) verifyActiveCheckpoint(file *os.File, size int64, head audit.SessionRecordingZstdHead, ctx context.Context) error {
	if size < 0 || uint64(size) != head.PrefixBytes {
		return errors.System.Newf("active Cast Zstandard container does not exactly match its signed checkpoint size")
	}
	options := this.options
	options.Context = ctx
	return verifyActiveCastZstdCheckpoint(file, size, head, options)
}

func (this *localCastZstdFormat) verifyWorkCheckpoint(file *os.File, size int64, head audit.SessionRecordingZstdHead, ctx context.Context) error {
	return this.verifyWorkCheckpointReader(file, size, head, ctx)
}

func (this *localCastZstdFormat) verifyWorkCheckpointReader(source io.ReaderAt, size int64, head audit.SessionRecordingZstdHead, ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	options, err := this.workVerifyOptions(ctx)
	if err != nil {
		return err
	}
	if size < 0 || uint64(size) != head.PrefixBytes {
		return invalidLocalArtifact(errors.System.Newf("active Cast Zstandard container does not exactly match its signed checkpoint size"))
	}
	reader := &localTrackingReaderAt{source: source, size: size}
	verifyErr := verifyActiveCastZstdCheckpoint(reader, size, head, options)
	if err := ctx.Err(); err != nil {
		return err
	}
	if reader.failure != nil {
		return errors.System.Newf("cannot read recording work content: %w", reader.failure)
	}
	return invalidLocalArtifact(verifyErr)
}

func (this *localCastZstdFormat) workVerifyOptions(ctx context.Context) (CastZstdVerifyOptions, error) {
	options := this.options
	options.Context = ctx
	if options.MaximumContainerBytes < 0 {
		return CastZstdVerifyOptions{}, errors.Config.Newf("maximum Cast Zstandard container size must be positive")
	}
	if options.MaximumCastBytes < 0 {
		return CastZstdVerifyOptions{}, errors.Config.Newf("maximum Cast size must be positive")
	}
	if options.MaximumContainerBytes < DefaultMaximumCastZstdBytes {
		options.MaximumContainerBytes = DefaultMaximumCastZstdBytes
	}
	if options.MaximumCastBytes < DefaultMaximumCastBytes {
		options.MaximumCastBytes = DefaultMaximumCastBytes
	}
	if options.MaximumChunks < DefaultMaximumCastZstdChunks {
		options.MaximumChunks = DefaultMaximumCastZstdChunks
	}
	return options, nil
}

func verifyActiveCastZstdCheckpoint(source io.ReaderAt, size int64, head audit.SessionRecordingZstdHead, options CastZstdVerifyOptions) error {
	stream, err := newCastZstdStreamForRecovery(source, size, options, &head, true)
	if err != nil {
		return err
	}
	defer stream.close()
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return err
	}
	if stream.seal != nil || stream.incompleteTail || stream.validEnd != size {
		return errors.System.Newf("new active recording has an unexpected container state")
	}
	return nil
}

func (this *localCastZstdFormat) recover(file RecoveryFile, head audit.SessionRecordingZstdHead, recoveredAt time.Time, ctx context.Context) (localRecovery[CastZstdSummary], error) {
	options := this.options
	options.Context = ctx
	result, err := RecoverCastZstd(file, this.identity, head, recoveredAt, options)
	if err != nil {
		return localRecovery[CastZstdSummary]{}, err
	}
	return localRecovery[CastZstdSummary]{
		summary:       result.Verification.Summary,
		truncated:     result.Truncated,
		alreadySealed: result.AlreadySealed,
	}, nil
}

func (this *localCastZstdFormat) verifyPublished(file *os.File, size int64, head *audit.SessionRecordingZstdHead, ctx context.Context) (CastZstdSummary, error) {
	options := this.options
	options.Context = ctx
	if head != nil {
		stream, err := newCastZstdStreamForRecovery(file, size, options, head, true)
		if err != nil {
			return CastZstdSummary{}, err
		}
		_, scanErr := io.Copy(io.Discard, stream)
		stream.close()
		if scanErr != nil {
			return CastZstdSummary{}, scanErr
		}
		if stream.seal == nil {
			return CastZstdSummary{}, errors.System.Newf("published Cast Zstandard container has no seal")
		}
	}
	verification, err := VerifyCastZstd(file, size, options)
	if err != nil {
		return CastZstdSummary{}, err
	}
	return verification.Summary, nil
}

func (this *localCastZstdFormat) summaryId(summary CastZstdSummary) Id {
	return summary.RecordingId
}

func (this *localCastZstdFormat) summaryDigest(summary CastZstdSummary) CastDigest {
	return summary.Digest
}
