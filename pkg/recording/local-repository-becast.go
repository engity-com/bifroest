package recording

import (
	"bytes"
	"context"
	"io"
	"os"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	localBECastFormatKey       = "becast/v1"
	localBECastContentFileName = "recording.becast"
	localBECastSealedSuffix    = ".becast"
)

type LocalBECastRepository struct {
	repository *localRepository[audit.SessionRecordingBECastHead, BECastSummary]
}

type RecoveredBECast struct {
	Summary       BECastSummary
	Truncated     bool
	AlreadySealed bool
}

type ActiveBECast struct {
	active *localActive[audit.SessionRecordingBECastHead, BECastSummary]
}

type localBECastFormat struct {
	identity  *audit.Identity
	recipient *crypto.AgeSshRecipient
	options   BECastVerifyOptions
}

func NewLocalBECastRepository(ctx context.Context, directory string, identity *audit.Identity, recipient *crypto.AgeSshRecipient, options BECastVerifyOptions) (*LocalBECastRepository, error) {
	if identity == nil || identity.PublicKey() == nil {
		return nil, errors.Config.Newf("nil local recording identity")
	}
	if recipient == nil || recipient.Fingerprint() == "" {
		return nil, errors.Config.Newf("nil local BECast age SSH recipient")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	options.ExpectedProducerId = identity.ProducerId()
	options.AllowUntrusted = false
	options.Context = ctx
	format := &localBECastFormat{identity: identity, recipient: recipient, options: options}
	repository, err := newLocalRepository(ctx, directory, identity, format)
	if err != nil {
		return nil, err
	}
	return &LocalBECastRepository{repository: repository}, nil
}

func (this *LocalBECastRepository) StartupRecoveries() []RecoveredBECast {
	if this == nil || this.repository == nil {
		return nil
	}
	recovered := this.repository.startupRecoveries()
	result := make([]RecoveredBECast, len(recovered))
	for index, current := range recovered {
		result[index] = RecoveredBECast{
			Summary:       current.summary,
			Truncated:     current.truncated,
			AlreadySealed: current.alreadySealed,
		}
	}
	return result
}

func (this *LocalBECastRepository) CreateActive(ctx context.Context, header CastHeader, metadata CastMetadata, chunkSize int) (*ActiveBECast, error) {
	if this == nil {
		return nil, errors.System.Newf("nil local recording repository")
	}
	active, err := this.repository.createActive(ctx, header, metadata, chunkSize)
	if err != nil {
		return nil, err
	}
	return &ActiveBECast{active: active}, nil
}

func (this *LocalBECastRepository) Close() error {
	if this == nil {
		return nil
	}
	return this.repository.close()
}

func (this *ActiveBECast) WriteOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	return this.local().writeOutput(elapsed, stream, data)
}

func (this *ActiveBECast) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	return this.local().writeResize(elapsed, columns, rows)
}

func (this *ActiveBECast) WriteMarker(elapsed time.Duration, label string) error {
	return this.local().writeMarker(elapsed, label)
}

func (this *ActiveBECast) Checkpoint() error {
	return this.local().checkpoint()
}

func (this *ActiveBECast) Seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (BECastSummary, error) {
	return this.local().seal(elapsed, result, exitStatus)
}

func (this *ActiveBECast) Close() error {
	return this.local().closeAndRemove()
}

func (this *ActiveBECast) local() *localActive[audit.SessionRecordingBECastHead, BECastSummary] {
	if this == nil {
		return nil
	}
	return this.active
}

func (this *localBECastFormat) key() string {
	return localBECastFormatKey
}

func (this *localBECastFormat) contentFileName() string {
	return localBECastContentFileName
}

func (this *localBECastFormat) sealedSuffix() string {
	return localBECastSealedSuffix
}

func (this *localBECastFormat) maximumHeadBytes() int64 {
	return maximumCastBECastHeadBytes
}

func (this *localBECastFormat) newWriter(output io.Writer, header CastHeader, metadata CastMetadata, chunkSize int) (localWriter[audit.SessionRecordingBECastHead, BECastSummary], error) {
	return NewBECastWriter(output, this.identity, this.recipient, header, metadata, chunkSize)
}

func (this *localBECastFormat) encodeHead(head audit.SessionRecordingBECastHead) ([]byte, error) {
	return encodeBECastHead(head)
}

func (this *localBECastFormat) decodeHead(payload []byte) (audit.SessionRecordingBECastHead, error) {
	return decodeBECastHead(payload)
}

func (this *localBECastFormat) headId(head audit.SessionRecordingBECastHead) Id {
	return Id(head.RecordingId)
}

func (this *localBECastFormat) headProducerId(head audit.SessionRecordingBECastHead) audit.ProducerId {
	return head.ProducerId
}

func (this *localBECastFormat) headPrefixBytes(head audit.SessionRecordingBECastHead) uint64 {
	return head.PrefixBytes
}

func (this *localBECastFormat) preflight(file *os.File, size int64, head audit.SessionRecordingBECastHead, ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	headerBytes := len(castBECastFileMagic) + castBECastUnitPrefixSize + castBECastHeaderBodySize + castBECastUnitTrailerSize
	if size < int64(headerBytes) {
		return invalidLocalArtifact(errors.System.Newf("BECast container is shorter than its clear header"))
	}
	payload := make([]byte, headerBytes)
	read, err := file.ReadAt(payload, 0)
	if err != nil {
		return errors.System.Newf("cannot read BECast clear header: %w", err)
	}
	if read != len(payload) {
		return errors.System.Newf("cannot read BECast clear header: %w", io.ErrUnexpectedEOF)
	}
	if !bytes.Equal(payload[:len(castBECastFileMagic)], []byte(castBECastFileMagic)) {
		return invalidLocalArtifact(errors.System.Newf("BECast file magic mismatch"))
	}
	header, err := decodeBECastHeader(payload[len(castBECastFileMagic):])
	if err != nil {
		return invalidLocalArtifact(err)
	}
	if header.FormatVersion != castBECastFormatVersion || header.CastVersion != castVersion || header.Codec != castBECastCodec || header.Encryption != castBECastEncryption {
		return invalidLocalArtifact(errors.System.Newf("unsupported BECast header version, codec, or encryption"))
	}
	if _, err := audit.VerifySessionRecordingBECastHeader(header); err != nil {
		return invalidLocalArtifact(err)
	}
	if Id(header.RecordingId) != this.headId(head) || header.ProducerId != this.headProducerId(head) || header.ProducerId != this.identity.ProducerId() {
		return invalidLocalArtifact(errors.System.Newf("BECast clear header does not match its recording head or repository identity"))
	}
	if header.RecipientFingerprint != this.recipient.Fingerprint() {
		return errors.Config.Newf("BECast recipient does not match its container")
	}
	return nil
}

func (this *localBECastFormat) verifyActiveCheckpoint(file *os.File, size int64, head audit.SessionRecordingBECastHead, ctx context.Context) error {
	return this.verifyCheckpointReader(file, size, head, ctx)
}

func (this *localBECastFormat) verifyWorkCheckpoint(file *os.File, size int64, head audit.SessionRecordingBECastHead, ctx context.Context) error {
	return this.verifyWorkCheckpointReader(file, size, head, ctx)
}

func (this *localBECastFormat) verifyCheckpointReader(source io.ReaderAt, size int64, head audit.SessionRecordingBECastHead, ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	options, err := this.scanOptions(ctx)
	if err != nil {
		return err
	}
	if size < 0 || uint64(size) != head.PrefixBytes {
		return errors.System.Newf("active BECast container does not exactly match its signed checkpoint size")
	}
	scan, scanErr := scanActiveBECast(source, size, options, head)
	if err := ctx.Err(); err != nil {
		return err
	}
	if scanErr == nil && (scan.incompleteTail || scan.seal != nil || scan.validEnd != size) {
		scanErr = errors.System.Newf("active BECast container has an unexpected container state")
	}
	return scanErr
}

func (this *localBECastFormat) verifyWorkCheckpointReader(source io.ReaderAt, size int64, head audit.SessionRecordingBECastHead, ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	options, err := this.workScanOptions(ctx)
	if err != nil {
		return err
	}
	if size < 0 || uint64(size) != head.PrefixBytes {
		return invalidLocalArtifact(errors.System.Newf("active BECast container does not exactly match its signed checkpoint size"))
	}
	reader := &localTrackingReaderAt{source: source, size: size}
	scan, scanErr := scanActiveBECast(reader, size, options, head)
	if err := ctx.Err(); err != nil {
		return err
	}
	if reader.failure != nil {
		return errors.System.Newf("cannot read recording work content: %w", reader.failure)
	}
	if scanErr == nil && scan.scanner.header.RecipientFingerprint != this.recipient.Fingerprint() {
		return errors.Config.Newf("BECast recipient does not match its container")
	}
	if scanErr == nil && (scan.incompleteTail || scan.seal != nil || scan.validEnd != size) {
		scanErr = errors.System.Newf("active BECast container has an unexpected container state")
	}
	return invalidLocalArtifact(scanErr)
}

func (this *localBECastFormat) scanOptions(ctx context.Context) (BECastVerifyOptions, error) {
	options := this.options
	options.Context = ctx
	if options.MaximumContainerBytes < 0 {
		return BECastVerifyOptions{}, errors.Config.Newf("maximum BECast container size must be positive")
	}
	if options.MaximumCastBytes < 0 {
		return BECastVerifyOptions{}, errors.Config.Newf("maximum Cast size must be positive")
	}
	if options.MaximumContainerBytes == 0 {
		options.MaximumContainerBytes = DefaultMaximumBECastBytes
	}
	if options.MaximumCastBytes == 0 {
		options.MaximumCastBytes = DefaultMaximumCastBytes
	}
	if options.MaximumChunks == 0 {
		options.MaximumChunks = DefaultMaximumBECastChunks
	}
	return options, nil
}

func (this *localBECastFormat) workScanOptions(ctx context.Context) (BECastVerifyOptions, error) {
	options, err := this.scanOptions(ctx)
	if err != nil {
		return BECastVerifyOptions{}, err
	}
	if options.MaximumContainerBytes < DefaultMaximumBECastBytes {
		options.MaximumContainerBytes = DefaultMaximumBECastBytes
	}
	if options.MaximumCastBytes < DefaultMaximumCastBytes {
		options.MaximumCastBytes = DefaultMaximumCastBytes
	}
	if options.MaximumChunks < DefaultMaximumBECastChunks {
		options.MaximumChunks = DefaultMaximumBECastChunks
	}
	return options, nil
}

func (this *localBECastFormat) recover(file RecoveryFile, head audit.SessionRecordingBECastHead, recoveredAt time.Time, ctx context.Context) (localRecovery[BECastSummary], error) {
	options, err := this.recoveryOptions(ctx)
	if err != nil {
		return localRecovery[BECastSummary]{}, err
	}
	result, err := RecoverBECast(file, this.identity, this.recipient, head, recoveredAt, options)
	if err != nil {
		return localRecovery[BECastSummary]{}, err
	}
	return localRecovery[BECastSummary]{
		summary:       result.Verification.Summary,
		truncated:     result.Truncated,
		alreadySealed: result.AlreadySealed,
	}, nil
}

func (this *localBECastFormat) recoveryOptions(ctx context.Context) (BECastVerifyOptions, error) {
	return this.scanOptions(ctx)
}

func (this *localBECastFormat) verifyPublished(file *os.File, size int64, head *audit.SessionRecordingBECastHead, ctx context.Context) (BECastSummary, error) {
	options := this.options
	options.Context = ctx
	if head != nil {
		scanOptions, err := this.scanOptions(ctx)
		if err != nil {
			return BECastSummary{}, err
		}
		scan, err := scanActiveBECast(file, size, scanOptions, *head)
		if err != nil {
			return BECastSummary{}, err
		}
		if scan.incompleteTail || scan.seal == nil || scan.validEnd != size {
			return BECastSummary{}, errors.System.Newf("published BECast container is not exactly complete and sealed")
		}
	}
	verification, err := VerifyBECast(file, size, options)
	if err != nil {
		return BECastSummary{}, err
	}
	return verification.Summary, nil
}

func (this *localBECastFormat) summaryId(summary BECastSummary) Id {
	return summary.RecordingId
}
