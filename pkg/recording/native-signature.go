package recording

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

const (
	nativeRecordingHeaderDomain  = cast.NativeRecordingHeaderDomain
	nativeRecordingChunkDomain   = cast.NativeRecordingChunkDomain
	nativeRecordingSealDomain    = cast.NativeRecordingSealDomain
	nativeRecordingHeadDomain    = cast.NativeRecordingHeadDomain
	nativeRecordingUnitDomain    = cast.NativeRecordingUnitDomain
	nativeRecordingContentDomain = cast.NativeRecordingContentDomain
)

// These aliases expose the fixed version-1 wire fields to a future repository
// adapter without changing the CBOR schemas in native-wire.go.
type NativeRecordingHeader = nativeRecordingHeader
type NativeRecordingChunk = nativeRecordingChunk
type NativeRecordingSeal = nativeRecordingSeal

type NativeRecordingHead = cast.NativeRecordingHead

type NativeRecordingSigner struct {
	identity *audit.Identity
}

func NewNativeRecordingSigner(identity *audit.Identity) (*NativeRecordingSigner, error) {
	if identity == nil || identity.PublicKey() == nil {
		return nil, fmt.Errorf("missing native recording signing identity")
	}
	return &NativeRecordingSigner{identity: identity}, nil
}

func nativeRecordingRecipientValid(value string) bool {
	return cast.NativeRecordingRecipientValid(value)
}

func nativeRecordingHeaderFields(h nativeRecordingHeader) map[uint64]any {
	return cast.NativeRecordingHeaderFields(h)
}

func nativeRecordingChunkFields(c nativeRecordingChunk) map[uint64]any {
	return cast.NativeRecordingChunkFields(c)
}

func nativeRecordingHash(domain string, data []byte) [32]byte {
	return cast.NativeRecordingHash(domain, data)
}

func nativeRecordingVerify(key ed25519.PublicKey, domain string, fields map[uint64]any, signature []byte, maximum int) error {
	return cast.NativeRecordingVerify(key, domain, fields, signature, maximum)
}

// Header signs a header payload; the adapter frames and commits it after the
// recording magic. An empty recipient means clear .bcast.
func (s *NativeRecordingSigner) Header(id Id, startedAt time.Time, recipient string) ([]byte, error) {
	if s == nil || s.identity == nil || validateId(id) != nil || startedAt.IsZero() || startedAt.Location() != time.UTC || (recipient != "" && (!nativeRecordingRecipientValid(recipient) || recipient == s.identity.Fingerprint())) {
		return nil, fmt.Errorf("invalid native recording header arguments")
	}
	h := nativeRecordingHeader{Version: 1, RecordingId: [16]byte(id), ProducerId: [32]byte(s.identity.ProducerId()), PublicKey: s.identity.PublicKey().Marshal(), StartedAt: nativeformat.TimestampOf(startedAt), Recipient: recipient}
	if recipient != "" {
		h.Encryption = 1
	}
	var err error
	h.Signature, err = s.identity.SignNativeRecordingHeader(audit.NativeRecordingHeaderContent{
		Version: h.Version, Encryption: h.Encryption, RecordingId: h.RecordingId,
		ProducerId: h.ProducerId, PublicKey: h.PublicKey, StartedAt: h.StartedAt, Recipient: h.Recipient,
	})
	if err != nil {
		return nil, err
	}
	return nativeformat.Marshal(h, nativeformat.MaxMetadataPayload)
}

// Chunk signs a bounded, already compressed (and optionally encrypted) CBOR
// event group. This primitive does not certify inner event or Cast semantics.
func (s *NativeRecordingSigner) Chunk(c nativeRecordingChunk) ([]byte, error) {
	if s == nil || s.identity == nil {
		return nil, fmt.Errorf("missing native recording signing identity")
	}
	if c.Sequence == 0 || len(c.StoredPayload) == 0 || len(c.StoredPayload) > nativeformat.MaxRecordingChunkPayload-256 || c.StoredHash != sha256.Sum256(c.StoredPayload) {
		return nil, fmt.Errorf("invalid native recording chunk descriptor")
	}
	if err := c.ValidateNativeWire(); err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(c.StoredPayload, []byte(nativeRecordingAgePrefix)) {
		decoded, err := nativeformat.DecodeStoredPayload(c.StoredPayload, nil, "", nativeformat.PayloadLimits{MaxDecoded: nativeformat.MaxRecordingDecodedChunk, MaxStored: nativeformat.MaxRecordingChunkPayload})
		if err != nil || len(decoded) != int(c.DecodedLength) {
			return nil, fmt.Errorf("invalid native recording compressed chunk: %v", err)
		}
		if _, err := nativeformat.Unmarshal[map[uint64]any](decoded, nativeformat.MaxRecordingDecodedChunk); err != nil {
			return nil, fmt.Errorf("invalid native recording CBOR chunk: %w", err)
		}
	}
	var err error
	c.Signature, err = s.identity.SignNativeRecordingChunk(audit.NativeRecordingChunkContent{
		Sequence: c.Sequence, PreviousUnitHash: c.PreviousUnitHash, DecodedLength: c.DecodedLength,
		StoredPayload: c.StoredPayload, StoredHash: c.StoredHash, CastHashState: c.CastHashState, CastHashBytes: c.CastHashBytes,
		FinalStatus: c.FinalStatus, CastDigest: c.CastDigest, CastSignature: c.CastSignature, CastBytes: c.CastBytes, EndedAt: c.EndedAt, LastElapsedNanos: c.LastElapsedNanos,
	})
	if err != nil {
		return nil, err
	}
	return nativeformat.Marshal(c, nativeformat.MaxRecordingChunkPayload)
}

// Seal requires a previously signed standalone Cast digest and signature.
func (s *NativeRecordingSigner) Seal(seal nativeRecordingSeal, id Id) ([]byte, error) {
	if s == nil || s.identity == nil || validateId(id) != nil {
		return nil, fmt.Errorf("invalid native recording seal signer")
	}
	if err := validateNativeRecordingSeal(seal, nativeRecordingHeader{RecordingId: [16]byte(id), ProducerId: [32]byte(s.identity.ProducerId()), PublicKey: s.identity.PublicKey().Marshal()}); err != nil {
		return nil, err
	}
	var err error
	seal.Signature, err = s.identity.SignNativeRecordingSeal(audit.NativeRecordingSealContent{
		Status: seal.Status, ChunkCount: seal.ChunkCount, LastUnitHash: seal.LastUnitHash,
		ContentHash: seal.ContentHash, CastDigest: seal.CastDigest, CastSignature: seal.CastSignature,
		CastBytes: seal.CastBytes, EndedAt: seal.EndedAt,
	})
	if err != nil {
		return nil, err
	}
	return nativeformat.Marshal(seal, nativeformat.MaxMetadataPayload)
}

// Head returns canonical signed head.cbor bytes. Persist only after syncing
// the committed prefix; replace atomically and sync its parent directory.
func (s *NativeRecordingSigner) Head(head NativeRecordingHead) ([]byte, error) {
	if s == nil || s.identity == nil || head.Version != 1 || head.ProducerId != [32]byte(s.identity.ProducerId()) || validateId(Id(head.RecordingId)) != nil || head.ChunkCount == 0 || head.CastHashBytes == 0 || head.CastHashBytes%sha256.BlockSize != 0 || head.PrefixBytes <= uint64(len(nativeformat.RecordingMagic)) {
		return nil, fmt.Errorf("invalid native recording checkpoint")
	}
	var err error
	head.Signature, err = s.identity.SignNativeRecordingHead(audit.NativeRecordingHeadContent{
		Version: head.Version, RecordingId: head.RecordingId, ProducerId: head.ProducerId,
		PrefixBytes: head.PrefixBytes, ChunkCount: head.ChunkCount, LastUnitHash: head.LastUnitHash,
		CastHashState: head.CastHashState, CastHashBytes: head.CastHashBytes,
	})
	if err != nil {
		return nil, err
	}
	return nativeformat.Marshal(head, nativeformat.MaxMetadataPayload)
}

func verifyNativeRecordingHeader(payload []byte) (nativeRecordingHeader, ed25519.PublicKey, error) {
	return cast.VerifyNativeRecordingHeader(payload)
}
