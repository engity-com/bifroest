package recording

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"os"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const localNativeHeadFileName = "head.cbor"

type LocalNativeRecordingRepository struct {
	repository *localRepository[[]byte, NativeRecordingSummary]
}

type RecoveredNativeRecording struct {
	Summary       NativeRecordingSummary
	Truncated     bool
	AlreadySealed bool
}

type ActiveNativeRecording struct {
	active *localActive[[]byte, NativeRecordingSummary]
}

type localNativeRecordingFormat struct {
	identity      *audit.Identity
	recipient     *bfcrypto.AgeSshRecipient
	options       NativeRecordingVerifyOptions
	recordingOnly bool
}

func NewLocalNativeRecordingRepository(ctx context.Context, directory string, identity *audit.Identity, recipient *bfcrypto.AgeSshRecipient, options NativeRecordingVerifyOptions, repositoryOptions LocalRepositoryOptions) (*LocalNativeRecordingRepository, error) {
	return NewLocalNativeRecordingRepositoryWithArtifactPreparer(ctx, directory, identity, recipient, options, repositoryOptions, nil)
}

func NewLocalNativeRecordingRepositoryWithArtifactPreparer(ctx context.Context, directory string, identity *audit.Identity, recipient *bfcrypto.AgeSshRecipient, options NativeRecordingVerifyOptions, repositoryOptions LocalRepositoryOptions, preparer SealedArtifactPreparer) (*LocalNativeRecordingRepository, error) {
	if identity == nil || identity.PublicKey() == nil || recipient != nil && (recipient.Fingerprint() == "" || recipient.Fingerprint() == identity.Fingerprint()) {
		return nil, errors.Config.Newf("invalid native recording identity or recipient")
	}
	if options.MaximumContainerBytes < 0 || options.MaximumCastBytes < 0 {
		return nil, errors.Config.Newf("invalid native recording verification limits")
	}
	options.ExpectedProducerId = identity.ProducerId()
	options.AllowUntrusted = false
	format := &localNativeRecordingFormat{identity: identity, recipient: recipient, options: options, recordingOnly: repositoryOptions.RecordingOnly}
	repository, err := newLocalRepository(ctx, directory, identity, format, repositoryOptions, preparer)
	if err != nil {
		return nil, err
	}
	return &LocalNativeRecordingRepository{repository: repository}, nil
}

func (r *LocalNativeRecordingRepository) StartupRecoveries() []RecoveredNativeRecording {
	if r == nil || r.repository == nil {
		return nil
	}
	recovered := r.repository.startupRecoveries()
	result := make([]RecoveredNativeRecording, len(recovered))
	for i, current := range recovered {
		result[i] = RecoveredNativeRecording{current.summary, current.truncated, current.alreadySealed}
	}
	return result
}

func (r *LocalNativeRecordingRepository) ListSealed(ctx context.Context) ([]Id, error) {
	if r == nil || r.repository == nil {
		return nil, errors.System.Newf("nil local native recording repository")
	}
	return r.repository.listSealed(ctx)
}

func (r *LocalNativeRecordingRepository) RecordingStateExists(id Id) (bool, error) {
	if r == nil || r.repository == nil {
		return false, errors.System.Newf("nil local native recording repository")
	}
	return r.repository.recordingStateExists(id)
}

func (r *LocalNativeRecordingRepository) OpenSealed(ctx context.Context, id Id) (*LocalSealedArtifact[NativeRecordingSummary], error) {
	if r == nil || r.repository == nil {
		return nil, errors.System.Newf("nil local native recording repository")
	}
	return r.repository.openSealed(ctx, id)
}

func (r *LocalNativeRecordingRepository) DeleteSealed(ctx context.Context, id Id, digest ArtifactDigest, size int64) (bool, error) {
	if r == nil || r.repository == nil {
		return false, errors.System.Newf("nil local native recording repository")
	}
	return r.repository.deleteSealed(ctx, id, digest, size)
}

func (r *LocalNativeRecordingRepository) CreateActive(ctx context.Context, header CastHeader, metadata CastMetadata, chunkTarget int) (*ActiveNativeRecording, error) {
	if r == nil || r.repository == nil {
		return nil, errors.System.Newf("nil local native recording repository")
	}
	active, err := r.repository.createActive(ctx, header, metadata, chunkTarget)
	if err != nil {
		return nil, err
	}
	return &ActiveNativeRecording{active: active}, nil
}

func (r *LocalNativeRecordingRepository) Close() error {
	if r == nil {
		return nil
	}
	return r.repository.close(false)
}

func (r *LocalNativeRecordingRepository) CloseAfterAcceptedFailure() error {
	if r == nil {
		return nil
	}
	return r.repository.close(true)
}

func (a *ActiveNativeRecording) local() *localActive[[]byte, NativeRecordingSummary] {
	if a == nil {
		return nil
	}
	return a.active
}

func (a *ActiveNativeRecording) WriteOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	return a.local().writeOutput(elapsed, stream, data)
}
func (a *ActiveNativeRecording) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	return a.local().writeResize(elapsed, columns, rows)
}
func (a *ActiveNativeRecording) WriteMarker(elapsed time.Duration, label string) error {
	return a.local().writeMarker(elapsed, label)
}
func (a *ActiveNativeRecording) Checkpoint() error { return a.local().checkpoint() }
func (a *ActiveNativeRecording) Seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (NativeRecordingSummary, error) {
	return a.local().seal(elapsed, result, exitStatus)
}
func (a *ActiveNativeRecording) Close() error { return a.local().closeAndRemove() }

func (f *localNativeRecordingFormat) key() string {
	if f.recipient != nil {
		if f.recordingOnly {
			return "becast-cbor-recording-only/v1"
		}
		return "becast-cbor/v1"
	}
	if f.recordingOnly {
		return "bcast-recording-only/v1"
	}
	return "bcast/v1"
}
func (f *localNativeRecordingFormat) contentFileName() string {
	return "recording" + f.sealedSuffix()
}
func (f *localNativeRecordingFormat) headFileName() string { return localNativeHeadFileName }
func (f *localNativeRecordingFormat) sealedSuffix() string {
	if f.recipient != nil {
		return ".becast"
	}
	return ".bcast"
}
func (f *localNativeRecordingFormat) maximumHeadBytes() int64 { return nativeformat.MaxMetadataPayload }

type localNativeWriter struct {
	*NativeRecordingWriter
	output *NativeDurableRecordingOutput
}

func (f *localNativeRecordingFormat) newWriter(output io.Writer, header CastHeader, metadata CastMetadata, chunkSize int) (localWriter[[]byte, NativeRecordingSummary], error) {
	file, ok := output.(*localQuotaFile)
	if !ok {
		return nil, errors.System.Newf("native recording requires quota-accounted file")
	}
	durable, err := NewNativeDurableRecordingOutput(file)
	if err != nil {
		return nil, err
	}
	writer, err := NewNativeRecordingWriter(durable, f.identity, f.recipient, header, metadata, chunkSize, NativeRecordingWriterLimits{
		MaximumContainerBytes: f.options.MaximumContainerBytes, MaximumCastBytes: f.options.MaximumCastBytes, MaximumChunks: f.options.MaximumChunks,
	})
	if err != nil {
		return nil, err
	}
	return &localNativeWriter{writer, durable}, nil
}

func (w *localNativeWriter) replaceOutput(output io.Writer) error {
	file, ok := output.(*localQuotaFile)
	if !ok || w == nil || w.NativeRecordingWriter == nil || w.output == nil || w.output.poison != nil || w.NativeRecordingWriter.poisoned != nil {
		return errors.System.Newf("cannot replace native recording output")
	}
	info, err := file.Stat()
	if err != nil || info.Size() != w.output.offset {
		return errors.System.Newf("native recording output changed during publication: %v", err)
	}
	w.output.file = file
	w.NativeRecordingWriter.output = w.output
	return nil
}
func (w *localNativeWriter) repositoryFailure() error {
	if w == nil {
		return errors.System.Newf("nil native writer")
	}
	if w.output != nil && w.output.poison != nil {
		return w.output.poison
	}
	return w.NativeRecordingWriter.poisoned
}
func (w *localNativeWriter) release() error { return nil }

func (f *localNativeRecordingFormat) encodeHead(head []byte) ([]byte, error) {
	if _, err := f.decodeHead(head); err != nil {
		return nil, err
	}
	return bytes.Clone(head), nil
}
func (f *localNativeRecordingFormat) decodeHead(payload []byte) ([]byte, error) {
	head, err := nativeformat.Unmarshal[NativeRecordingHead](payload, nativeformat.MaxMetadataPayload)
	if err != nil || head.Version != 1 || head.ChunkCount == 0 || head.PrefixBytes == 0 || head.ProducerId != [32]byte(f.identity.ProducerId()) {
		return nil, errors.Config.Newf("invalid native recording head: %v", err)
	}
	return bytes.Clone(payload), nil
}
func (f *localNativeRecordingFormat) headId(payload []byte) Id {
	head, _ := nativeformat.Unmarshal[NativeRecordingHead](payload, nativeformat.MaxMetadataPayload)
	return Id(head.RecordingId)
}
func (f *localNativeRecordingFormat) headProducerId(payload []byte) audit.ProducerId {
	head, _ := nativeformat.Unmarshal[NativeRecordingHead](payload, nativeformat.MaxMetadataPayload)
	return audit.ProducerId(head.ProducerId)
}
func (f *localNativeRecordingFormat) headPrefixBytes(payload []byte) uint64 {
	head, _ := nativeformat.Unmarshal[NativeRecordingHead](payload, nativeformat.MaxMetadataPayload)
	return head.PrefixBytes
}

func (f *localNativeRecordingFormat) preflight(file *os.File, size int64, head []byte, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if size < int64(len(nativeformat.RecordingMagic))+18 || size > f.maximumContainerBytes() {
		return invalidLocalArtifact(errors.Config.Newf("invalid native recording size"))
	}
	magic := make([]byte, len(nativeformat.RecordingMagic))
	if _, err := file.ReadAt(magic, 0); err != nil {
		return errors.System.Newf("cannot read native recording magic: %w", err)
	}
	if string(magic) != nativeformat.RecordingMagic {
		return invalidLocalArtifact(errors.Config.Newf("native recording magic mismatch"))
	}
	unit, _, tail, err := nativeformat.ReadUnitAt(file, int64(len(magic)), size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
		return invalidLocalArtifact(errors.Config.Newf("invalid native recording header: %v", err))
	}
	header, _, err := verifyNativeRecordingHeader(unit.Payload)
	if err != nil || header.ProducerId != [32]byte(f.identity.ProducerId()) || Id(header.RecordingId) != f.headId(head) {
		return invalidLocalArtifact(errors.Config.Newf("native recording header identity mismatch: %v", err))
	}
	if f.recipient == nil && header.Encryption != 0 || f.recipient != nil && (header.Encryption != 1 || header.Recipient != f.recipient.Fingerprint()) {
		return errors.Config.Newf("native recording recipient or encryption mismatch")
	}
	if _, err := VerifyNativeRecordingHead(head, unit.Payload); err != nil {
		return invalidLocalArtifact(err)
	}
	startedAt, err := header.StartedAt.Time()
	if err != nil {
		return invalidLocalArtifact(err)
	}
	options := f.options
	options.Context = ctx
	// Head-temp cleanup is a separate, earlier trust boundary in the repository;
	// this scan protects the content before recovery reserve or recording mutation.
	view := &localNativeReadOnlyPrefix{io.NewSectionReader(file, 0, size)}
	_, err = RecoverNativeRecording(view, f.identity, f.recipient, head, startedAt, options)
	if err == nil || stderrors.Is(err, errNativeCheckpointValidated) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return invalidLocalArtifact(err)
}

func (f *localNativeRecordingFormat) maximumContainerBytes() int64 {
	if f.options.MaximumContainerBytes > 0 {
		return f.options.MaximumContainerBytes
	}
	return DefaultMaximumNativeRecordingBytes
}

var errNativeCheckpointValidated = stderrors.New("native checkpoint validated before mutation")

type localNativeReadOnlyPrefix struct{ *io.SectionReader }

func (*localNativeReadOnlyPrefix) Write([]byte) (int, error) { return 0, errNativeCheckpointValidated }
func (*localNativeReadOnlyPrefix) WriteAt([]byte, int64) (int, error) {
	return 0, errNativeCheckpointValidated
}
func (*localNativeReadOnlyPrefix) Truncate(int64) error { return errNativeCheckpointValidated }
func (*localNativeReadOnlyPrefix) Sync() error          { return errNativeCheckpointValidated }

func (f *localNativeRecordingFormat) verifyCheckpoint(file *os.File, size int64, head []byte, ctx context.Context, work bool) error {
	if size < 0 || uint64(size) != f.headPrefixBytes(head) {
		err := errors.Config.Newf("native recording does not match its signed checkpoint size")
		if work {
			return invalidLocalArtifact(err)
		}
		return err
	}
	options := f.options
	options.Context = ctx
	// A read-only exact-prefix view lets the recovery scanner validate the
	// complete signed chain without ever granting it mutation rights. Use the
	// signed start time so this check does not depend on the wall clock: a
	// previously sealed artifact can remain valid beyond the recording limit.
	unit, _, tail, err := nativeformat.ReadUnitAt(file, int64(len(nativeformat.RecordingMagic)), size, nativeformat.MaxMetadataPayload)
	if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
		return errors.Config.Newf("invalid native checkpoint header: %v", err)
	}
	header, _, err := verifyNativeRecordingHeader(unit.Payload)
	if err != nil {
		return err
	}
	startedAt, err := header.StartedAt.Time()
	if err != nil {
		return err
	}
	view := &localNativeReadOnlyPrefix{io.NewSectionReader(file, 0, size)}
	_, err = RecoverNativeRecording(view, f.identity, f.recipient, head, startedAt, options)
	if stderrors.Is(err, errNativeCheckpointValidated) {
		return nil
	}
	if work && err != nil && ctx.Err() == nil {
		return invalidLocalArtifact(err)
	}
	if err == nil {
		return errors.System.Newf("native active checkpoint unexpectedly sealed")
	}
	return err
}

func (f *localNativeRecordingFormat) verifyActiveCheckpoint(file *os.File, size int64, head []byte, ctx context.Context) error {
	return f.verifyCheckpoint(file, size, head, ctx, false)
}
func (f *localNativeRecordingFormat) verifyWorkCheckpoint(file *os.File, size int64, head []byte, ctx context.Context) error {
	return f.verifyCheckpoint(file, size, head, ctx, true)
}
func (f *localNativeRecordingFormat) recover(file RecoveryFile, head []byte, at time.Time, ctx context.Context) (localRecovery[NativeRecordingSummary], error) {
	native, ok := file.(NativeRecoveryFile)
	if !ok {
		return localRecovery[NativeRecordingSummary]{}, errors.System.Newf("native recovery requires quota-accounted WriteAt")
	}
	options := f.options
	options.Context = ctx
	result, err := RecoverNativeRecording(native, f.identity, f.recipient, head, at, options)
	if err != nil {
		return localRecovery[NativeRecordingSummary]{}, err
	}
	verification := result.Verification
	if f.recipient == nil && verification.Header.Encryption != 0 || f.recipient != nil && (verification.Header.Encryption != 1 || verification.Header.Recipient != f.recipient.Fingerprint()) {
		return localRecovery[NativeRecordingSummary]{}, errors.Config.Newf("recovered native recording encryption mismatch")
	}
	status, err := castStatusFromNativeRecording(verification.Seal.Status)
	if err != nil {
		return localRecovery[NativeRecordingSummary]{}, err
	}
	size, err := native.Seek(0, io.SeekEnd)
	if err != nil {
		return localRecovery[NativeRecordingSummary]{}, err
	}
	return localRecovery[NativeRecordingSummary]{summary: nativeSummary(verification, status, uint64(size)), truncated: result.Truncated, alreadySealed: result.AlreadySealed}, nil
}

func nativeSummary(v *NativeRecordingVerification, status CastStatus, size uint64) NativeRecordingSummary {
	return NativeRecordingSummary{
		RecordingId: Id(v.Header.RecordingId), ProducerId: audit.ProducerId(v.Header.ProducerId),
		RecipientFingerprint: v.Header.Recipient, Status: status, ChunkCount: v.Seal.ChunkCount,
		CastBytes: v.Seal.CastBytes, Digest: CastDigest(v.Seal.CastDigest), Bytes: size,
	}
}

func (f *localNativeRecordingFormat) verifyPublished(file *os.File, size int64, head *[]byte, ctx context.Context) (NativeRecordingSummary, error) {
	options := f.options
	options.Context = ctx
	var verification *NativeRecordingVerification
	var err error
	if f.recipient == nil {
		verification, err = VerifyNativeRecordingFull(file, size, nil, options)
	} else {
		verification, err = VerifyNativeRecordingOuter(file, size, options)
	}
	if err != nil {
		return NativeRecordingSummary{}, err
	}
	// Sealed recordings retain the recipient used when they were created;
	// only active recordings require the currently configured recipient.
	if f.recipient == nil && verification.Header.Encryption != 0 || f.recipient != nil && verification.Header.Encryption != 1 {
		return NativeRecordingSummary{}, errors.Config.Newf("published native recording encryption mismatch")
	}
	if head != nil {
		if err := VerifyNativeRecordingCheckpoint(file, size, *head, f.identity, options); err != nil {
			return NativeRecordingSummary{}, err
		}
	}
	status, err := castStatusFromNativeRecording(verification.Seal.Status)
	if err != nil {
		return NativeRecordingSummary{}, err
	}
	return nativeSummary(verification, status, uint64(size)), nil
}
func (f *localNativeRecordingFormat) summaryId(summary NativeRecordingSummary) Id {
	return summary.RecordingId
}
func (f *localNativeRecordingFormat) summaryDigest(summary NativeRecordingSummary) CastDigest {
	return summary.Digest
}
