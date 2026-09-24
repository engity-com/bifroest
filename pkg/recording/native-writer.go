package recording

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const DefaultNativeRecordingChunkTarget = 256 << 10

var nativeRecordingPayloadLimits = nativeformat.PayloadLimits{
	MaxDecoded: nativeformat.MaxRecordingDecodedChunk,
	MaxStored:  nativeformat.MaxRecordingChunkPayload,
}

type NativeRecordingWriterLimits struct {
	MaximumContainerBytes int64
	MaximumCastBytes      int64
	MaximumChunks         uint64
}

type NativeRecordingSummary struct {
	RecordingId          Id
	ProducerId           audit.ProducerId
	RecipientFingerprint string
	Status               CastStatus
	ChunkCount           uint64
	CastBytes            uint64
	Digest               CastDigest
	Bytes                uint64
}

// NativeRecordingWriter emits signed framed units. Plain io.Writer is only for
// in-memory/tests: it cannot durably sync the body and commit bit. A
// NativeRecordingUnitCommitter (such as NativeDurableRecordingOutput) commits
// each unit before the writer updates its hash chain. The repository still
// owns locking, quota, signed-head replacement and directory sync.
type NativeRecordingWriter struct {
	output       io.Writer
	signer       *NativeRecordingSigner
	identity     *audit.Identity
	recipient    *bfcrypto.AgeSshRecipient
	metadata     CastMetadata
	cast         *CastWriter
	castCounter  *nativeCastCounter
	limits       recordingWriterLimits
	target       int
	events       []NativeCastEvent
	contentHash  hash.Hash
	prefixBytes  uint64
	previousHash [32]byte
	lastCastHash castSha256Checkpoint
	chunkCount   uint64
	sealed       bool
	poisoned     error
}

type nativeCastCounter struct {
	bytes   uint64
	maximum uint64
}

func (c *nativeCastCounter) Write(value []byte) (int, error) {
	if uint64(len(value)) > c.maximum-c.bytes {
		return 0, fmt.Errorf("native recording Cast exceeds %d bytes", c.maximum)
	}
	c.bytes += uint64(len(value))
	return len(value), nil
}

func NewNativeRecordingWriter(output io.Writer, identity *audit.Identity, recipient *bfcrypto.AgeSshRecipient, header CastHeader, metadata CastMetadata, chunkTarget int, options NativeRecordingWriterLimits) (*NativeRecordingWriter, error) {
	if output == nil || identity == nil || identity.PublicKey() == nil {
		return nil, fmt.Errorf("missing native recording output or signing identity")
	}
	if _, unsafeFile := output.(*os.File); unsafeFile {
		return nil, fmt.Errorf("native recording file requires a durable unit-commit sink")
	}
	if recipient != nil && (recipient.Fingerprint() == "" || recipient.Fingerprint() == identity.Fingerprint()) {
		return nil, fmt.Errorf("native recording recipient must differ from signing identity")
	}
	if chunkTarget == 0 {
		chunkTarget = DefaultNativeRecordingChunkTarget
	}
	if chunkTarget < 1 || chunkTarget > nativeformat.MaxRecordingDecodedChunk {
		return nil, fmt.Errorf("invalid native recording chunk target")
	}
	limits, err := newRecordingWriterLimits(options.MaximumContainerBytes, options.MaximumCastBytes, options.MaximumChunks, DefaultMaximumBECastBytes, DefaultMaximumBECastChunks)
	if err != nil {
		return nil, err
	}
	if limits.maximumCastBytes > uint64(DefaultMaximumCastBytes) {
		return nil, fmt.Errorf("native recording Cast limit exceeds renderer maximum")
	}
	if limits.maximumChunks > DefaultMaximumBECastChunks {
		return nil, fmt.Errorf("native recording chunk limit exceeds renderer maximum")
	}
	signer, err := NewNativeRecordingSigner(identity)
	if err != nil {
		return nil, err
	}
	count := &nativeCastCounter{maximum: limits.maximumCastBytes}
	cast, err := NewCastWriter(count, identity, header, metadata)
	if err != nil {
		return nil, err
	}
	fingerprint := ""
	if recipient != nil {
		fingerprint = recipient.Fingerprint()
	}
	headerPayload, err := signer.Header(metadata.RecordingId, metadata.StartedAt, fingerprint)
	if err != nil {
		return nil, err
	}
	frame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, headerPayload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nil, err
	}
	prefix := append([]byte(nativeformat.RecordingMagic), frame...)
	if recordingCountExceedsLimit(0, uint64(len(prefix)), uint64(nativeformat.MaxMetadataPayload+18), limits.maximumContainerBytes) {
		return nil, fmt.Errorf("native recording container cannot fit header and seal")
	}
	if _, durable := output.(NativeRecordingUnitCommitter); durable {
		if err := writeNativeRecordingBytes(output, []byte(nativeformat.RecordingMagic)); err != nil {
			return nil, err
		}
		if err := writeNativeRecordingFrame(output, frame); err != nil {
			return nil, err
		}
	} else if err := writeNativeRecordingBytes(output, prefix); err != nil {
		return nil, err
	}
	contentHash := sha256.New()
	_, _ = contentHash.Write([]byte(nativeRecordingContentDomain))
	_, _ = contentHash.Write(prefix)
	return &NativeRecordingWriter{
		output: output, signer: signer, identity: identity, recipient: recipient,
		metadata: metadata, cast: cast, castCounter: count, target: chunkTarget, limits: limits,
		contentHash: contentHash, prefixBytes: uint64(len(prefix)),
		previousHash: nativeRecordingHash(nativeRecordingUnitDomain, frame),
		events:       []NativeCastEvent{{Kind: NativeEventSetup, Header: header, Metadata: metadata}},
	}, nil
}

func writeNativeRecordingBytes(output io.Writer, value []byte) error {
	n, err := output.Write(value)
	if err != nil {
		return fmt.Errorf("cannot write native recording: %w", err)
	}
	if n != len(value) {
		return fmt.Errorf("cannot write native recording: %w", io.ErrShortWrite)
	}
	return nil
}

func writeNativeRecordingFrame(output io.Writer, frame []byte) error {
	if durable, ok := output.(NativeRecordingUnitCommitter); ok {
		return durable.CommitNativeRecordingUnit(frame)
	}
	return writeNativeRecordingBytes(output, frame)
}

func (w *NativeRecordingWriter) ready() error {
	if w == nil || w.cast == nil {
		return fmt.Errorf("nil native recording writer")
	}
	if w.poisoned != nil {
		return w.poisoned
	}
	if w.sealed {
		return fmt.Errorf("native recording writer is sealed")
	}
	return nil
}

func (w *NativeRecordingWriter) poison(err error) error {
	if w.poisoned == nil {
		w.poisoned = err
	}
	return err
}

func (w *NativeRecordingWriter) prepare(event NativeCastEvent) error {
	if _, err := EncodeNativeRecordingEvents([]NativeCastEvent{event}); err != nil {
		return err
	}
	candidate := append(append([]NativeCastEvent(nil), w.events...), event, NativeCastEvent{Kind: NativeEventPaddingCheckpoint})
	encoded, err := EncodeNativeRecordingEvents(candidate)
	if err != nil || len(encoded) > w.target && len(w.events) > 0 {
		if err := w.Flush(); err != nil {
			return err
		}
		candidate = []NativeCastEvent{event, {Kind: NativeEventPaddingCheckpoint}}
		if _, err := EncodeNativeRecordingEvents(candidate); err != nil {
			return err
		}
	}
	return nil
}

func (w *NativeRecordingWriter) WriteOutput(elapsed time.Duration, stream OutputStream, data []byte) error {
	if err := w.ready(); err != nil {
		return err
	}
	if err := w.cast.validateOutputStream(stream); err != nil {
		return err
	}
	if err := w.cast.validateElapsed(elapsed); err != nil {
		return err
	}
	for offset := 0; offset < len(data); {
		end := castOutputChunkEnd(data, offset)
		event := NativeCastEvent{Kind: NativeEventOutput, Elapsed: elapsed, Stream: stream, Data: append([]byte(nil), data[offset:end]...)}
		if err := w.prepare(event); err != nil {
			return w.poison(err)
		}
		if err := w.cast.WriteOutput(elapsed, stream, event.Data); err != nil {
			return w.poison(err)
		}
		w.events = append(w.events, event)
		offset = end
	}
	return nil
}

func (w *NativeRecordingWriter) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	if err := w.ready(); err != nil {
		return err
	}
	if !w.metadata.Pty || columns == 0 || rows == 0 || columns > MaximumCastTerminalDimension || rows > MaximumCastTerminalDimension {
		return fmt.Errorf("invalid native recording resize")
	}
	if err := w.cast.validateElapsed(elapsed); err != nil {
		return err
	}
	event := NativeCastEvent{Kind: NativeEventResize, Elapsed: elapsed, Columns: columns, Rows: rows}
	if err := w.prepare(event); err != nil {
		return w.poison(err)
	}
	if err := w.cast.WriteResize(elapsed, columns, rows); err != nil {
		return w.poison(err)
	}
	w.events = append(w.events, event)
	return nil
}

func (w *NativeRecordingWriter) WriteMarker(elapsed time.Duration, label string) error {
	if err := w.ready(); err != nil {
		return err
	}
	if err := w.cast.validateElapsed(elapsed); err != nil {
		return err
	}
	event := NativeCastEvent{Kind: NativeEventMarker, Elapsed: elapsed, Label: label}
	if err := w.prepare(event); err != nil {
		return w.poison(err)
	}
	if err := w.cast.WriteMarker(elapsed, label); err != nil {
		return w.poison(err)
	}
	w.events = append(w.events, event)
	return nil
}

// Flush ends a nonfinal group with exactly the same Cast padding comment as
// the decoder will regenerate. Plain io.Writer has no durability guarantee.
func (w *NativeRecordingWriter) Flush() error {
	if err := w.ready(); err != nil {
		return err
	}
	if len(w.events) == 0 {
		return nil
	}
	if w.chunkCount >= w.limits.maximumChunks-1 {
		return fmt.Errorf("native recording has no room for a final chunk")
	}
	events := append(append([]NativeCastEvent(nil), w.events...), NativeCastEvent{Kind: NativeEventPaddingCheckpoint})
	decoded, err := EncodeNativeRecordingEvents(events)
	if err != nil {
		return w.poison(err)
	}
	checkpoint, err := padCastForSha256Checkpoint(w.cast)
	if err != nil {
		return w.poison(err)
	}
	lastElapsed := uint64(w.cast.lastElapsed)
	chunk := nativeRecordingChunk{Sequence: w.chunkCount + 1, PreviousUnitHash: w.previousHash, DecodedLength: uint32(len(decoded)), CastHashState: checkpoint.State, CastHashBytes: checkpoint.Bytes, LastElapsedNanos: &lastElapsed}
	if err := w.writeChunk(decoded, chunk); err != nil {
		return w.poison(err)
	}
	w.lastCastHash = checkpoint
	w.events = nil
	return nil
}

// Checkpoint returns signed head.cbor bytes for the last completed chunk. It
// must be persisted only after the owning adapter has committed and synced the
// exact prefix, atomically replaced head.cbor, and synced its directory.
func (w *NativeRecordingWriter) Checkpoint() ([]byte, error) {
	if err := w.Flush(); err != nil {
		return nil, err
	}
	head := NativeRecordingHead{
		Version: 1, RecordingId: [16]byte(w.metadata.RecordingId), ProducerId: [32]byte(w.metadata.ProducerId),
		PrefixBytes: w.prefixBytes, ChunkCount: w.chunkCount, LastUnitHash: w.previousHash,
		CastHashState: w.lastCastHash.State, CastHashBytes: w.lastCastHash.Bytes,
	}
	payload, err := w.signer.Head(head)
	if err != nil {
		return nil, w.poison(err)
	}
	return payload, nil
}

// Seal writes the final signed chunk and seal. It never writes a .cast file.
func (w *NativeRecordingWriter) Seal(elapsed time.Duration, result CastResult, exitStatus *uint32) (NativeRecordingSummary, error) {
	if err := w.ready(); err != nil {
		return NativeRecordingSummary{}, err
	}
	status := nativeStatusNumber(result.Status)
	if status == 0 {
		return NativeRecordingSummary{}, fmt.Errorf("invalid native recording result status")
	}
	event := NativeCastEvent{Kind: NativeEventResult, Elapsed: elapsed, Result: result}
	if exitStatus != nil {
		value := *exitStatus
		event.ExitStatus = &value
	}
	if err := w.prepare(event); err != nil {
		return NativeRecordingSummary{}, w.poison(err)
	}
	digest, err := w.cast.Seal(elapsed, result, event.ExitStatus)
	if err != nil {
		return NativeRecordingSummary{}, w.poison(err)
	}
	w.events = append(w.events, event)
	decoded, err := EncodeNativeRecordingEvents(w.events)
	if err != nil {
		return NativeRecordingSummary{}, w.poison(err)
	}
	castSignature, err := w.identity.NewSessionRecordingCastSignature(w.metadata.RecordingId.String(), digest.String())
	if err != nil {
		return NativeRecordingSummary{}, w.poison(err)
	}
	finalDigest, castBytes := [32]byte(digest), w.castCounter.bytes
	endedAt := nativeformat.TimestampOf(result.EndedAt)
	chunk := nativeRecordingChunk{
		Sequence: w.chunkCount + 1, PreviousUnitHash: w.previousHash, DecodedLength: uint32(len(decoded)),
		CastHashState: finalDigest, FinalStatus: status, CastDigest: &finalDigest,
		CastSignature: castSignature.Signature, CastBytes: &castBytes,
		EndedAt: &endedAt,
	}
	if err := w.writeChunk(decoded, chunk); err != nil {
		return NativeRecordingSummary{}, w.poison(err)
	}
	var contentHash [32]byte
	copy(contentHash[:], w.contentHash.Sum(nil))
	seal := nativeRecordingSeal{
		Status: status, ChunkCount: w.chunkCount, LastUnitHash: w.previousHash,
		ContentHash: contentHash, CastDigest: finalDigest, CastSignature: castSignature.Signature,
		CastBytes: castBytes, EndedAt: endedAt,
	}
	sealPayload, err := w.signer.Seal(seal, w.metadata.RecordingId)
	if err != nil {
		return NativeRecordingSummary{}, w.poison(err)
	}
	frame, err := nativeformat.EncodeUnit(nativeformat.SealUnit, sealPayload, nativeformat.MaxMetadataPayload)
	if err != nil || recordingCountExceedsLimit(w.prefixBytes, uint64(len(frame)), 0, w.limits.maximumContainerBytes) {
		return NativeRecordingSummary{}, w.poison(fmt.Errorf("native recording seal exceeds container limit: %v", err))
	}
	if err := writeNativeRecordingFrame(w.output, frame); err != nil {
		return NativeRecordingSummary{}, w.poison(err)
	}
	w.prefixBytes += uint64(len(frame))
	w.sealed = true
	fingerprint := ""
	if w.recipient != nil {
		fingerprint = w.recipient.Fingerprint()
	}
	return NativeRecordingSummary{
		RecordingId: w.metadata.RecordingId, ProducerId: w.metadata.ProducerId,
		RecipientFingerprint: fingerprint,
		Status:               result.Status, ChunkCount: w.chunkCount, CastBytes: castBytes,
		Digest: digest, Bytes: w.prefixBytes,
	}, nil
}

func (w *NativeRecordingWriter) writeChunk(decoded []byte, chunk nativeRecordingChunk) error {
	if w.chunkCount >= w.limits.maximumChunks {
		return fmt.Errorf("native recording chunk limit exceeded")
	}
	stored, err := nativeformat.EncodeStoredPayload(decoded, w.recipient, nativeRecordingPayloadLimits)
	if err != nil {
		return err
	}
	chunk.StoredPayload, chunk.StoredHash = stored, sha256.Sum256(stored)
	payload, err := w.signer.Chunk(chunk)
	if err != nil {
		return err
	}
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxRecordingChunkPayload)
	if err != nil {
		return err
	}
	if recordingCountExceedsLimit(w.prefixBytes, uint64(len(frame)), uint64(nativeformat.MaxMetadataPayload+18), w.limits.maximumContainerBytes) {
		return fmt.Errorf("native recording exceeds container limit")
	}
	if err := writeNativeRecordingFrame(w.output, frame); err != nil {
		return err
	}
	_, _ = w.contentHash.Write(frame)
	w.prefixBytes += uint64(len(frame))
	w.previousHash = nativeRecordingHash(nativeRecordingUnitDomain, frame)
	w.chunkCount++
	return nil
}
