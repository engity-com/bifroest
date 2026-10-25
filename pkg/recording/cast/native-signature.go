package cast

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"golang.org/x/crypto/ssh"
)

const (
	nativeRecordingHeaderDomain  = "BIFROEST-BCAST-HEADER-SIGNATURE/v1\x00"
	nativeRecordingChunkDomain   = "BIFROEST-BCAST-CHUNK-SIGNATURE/v1\x00"
	nativeRecordingSealDomain    = "BIFROEST-BCAST-SEAL-SIGNATURE/v1\x00"
	nativeRecordingHeadDomain    = "BIFROEST-BCAST-HEAD-SIGNATURE/v1\x00"
	nativeRecordingUnitDomain    = "BIFROEST-BCAST-UNIT-HASH/v1\x00"
	nativeRecordingContentDomain = "BIFROEST-BCAST-CONTENT-HASH/v1\x00"
)

type NativeRecordingHeader = nativeRecordingHeader
type NativeRecordingChunk = nativeRecordingChunk
type NativeRecordingSeal = nativeRecordingSeal
type NativeRecordingHead struct {
	Version       uint8    `cbor:"1,keyasint"`
	RecordingId   [16]byte `cbor:"2,keyasint"`
	ProducerId    [32]byte `cbor:"3,keyasint"`
	PrefixBytes   uint64   `cbor:"4,keyasint"`
	ChunkCount    uint64   `cbor:"5,keyasint"`
	LastUnitHash  [32]byte `cbor:"6,keyasint"`
	CastHashState [32]byte `cbor:"7,keyasint"`
	CastHashBytes uint64   `cbor:"8,keyasint"`
	Signature     []byte   `cbor:"9,keyasint"`
}

var nativeRecordingPayloadLimits = nativeformat.PayloadLimits{MaxDecoded: nativeformat.MaxRecordingDecodedChunk, MaxStored: nativeformat.MaxRecordingChunkPayload}

func nativeRecordingRecipientValid(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "SHA256:")
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size && base64.RawStdEncoding.EncodeToString(decoded) == encoded
}
func nativeRecordingHeaderFields(h nativeRecordingHeader) map[uint64]any {
	fields := map[uint64]any{1: h.Version, 2: h.Encryption, 3: h.RecordingId, 4: h.ProducerId, 5: h.PublicKey, 6: h.StartedAt}
	if h.Recipient != "" {
		fields[7] = h.Recipient
	}
	return fields
}
func nativeRecordingChunkFields(c nativeRecordingChunk) map[uint64]any {
	fields := map[uint64]any{1: c.Sequence, 2: c.PreviousUnitHash, 3: c.DecodedLength, 4: c.StoredPayload, 5: c.StoredHash, 6: c.CastHashState, 7: c.CastHashBytes}
	if c.CastDigest != nil {
		fields[9], fields[10], fields[11], fields[12], fields[13] = c.FinalStatus, *c.CastDigest, c.CastSignature, *c.CastBytes, *c.EndedAt
	} else if c.LastElapsedNanos != nil {
		fields[14] = *c.LastElapsedNanos
	}
	return fields
}
func nativeRecordingSealFields(s nativeRecordingSeal) map[uint64]any {
	return map[uint64]any{1: s.Status, 2: s.ChunkCount, 3: s.LastUnitHash, 4: s.ContentHash, 5: s.CastDigest, 6: s.CastSignature, 7: s.CastBytes, 8: s.EndedAt}
}
func nativeRecordingHeadFields(h NativeRecordingHead) map[uint64]any {
	return map[uint64]any{1: h.Version, 2: h.RecordingId, 3: h.ProducerId, 4: h.PrefixBytes, 5: h.ChunkCount, 6: h.LastUnitHash, 7: h.CastHashState, 8: h.CastHashBytes}
}
func nativeRecordingHash(domain string, data []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(data)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
func nativeRecordingVerify(key ed25519.PublicKey, domain string, fields map[uint64]any, signature []byte, maximum int) error {
	unsigned, err := nativeformat.Marshal(fields, maximum)
	if err != nil {
		return err
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(domain), unsigned...), signature) {
		return fmt.Errorf("invalid native recording signature")
	}
	return nil
}
func verifyNativeRecordingHeader(payload []byte) (nativeRecordingHeader, ed25519.PublicKey, error) {
	h, err := nativeformat.Unmarshal[nativeRecordingHeader](payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return h, nil, err
	}
	key, err := bfcrypto.ParsePublicKeyBytes(h.PublicKey)
	if err != nil || key == nil || !bytes.Equal(key.Marshal(), h.PublicKey) {
		return h, nil, fmt.Errorf("invalid native recording public key: %v", err)
	}
	ed, ok := key.ToSdk().(ed25519.PublicKey)
	if !ok || len(ed) != ed25519.PublicKeySize || h.ProducerId != sha256.Sum256(h.PublicKey) || h.Version != 1 || h.Encryption > 1 || (h.Encryption == 1) != (h.Recipient != "") || (h.Recipient != "" && (!nativeRecordingRecipientValid(h.Recipient) || h.Recipient == ssh.FingerprintSHA256(key.ToSsh()))) || validateId(Id(h.RecordingId)) != nil {
		return h, nil, fmt.Errorf("invalid native recording header identity, version or mode")
	}
	if at, err := h.StartedAt.Time(); err != nil || at.IsZero() {
		return h, nil, fmt.Errorf("invalid native recording start time")
	}
	if err := nativeRecordingVerify(ed, nativeRecordingHeaderDomain, nativeRecordingHeaderFields(h), h.Signature, nativeformat.MaxMetadataPayload); err != nil {
		return h, nil, err
	}
	return h, ed, nil
}
