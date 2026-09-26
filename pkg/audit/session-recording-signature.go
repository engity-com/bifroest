package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	SessionRecordingCastSignatureSchema = "bifroest.asciicast-signature/v1"
	sessionRecordingCastSignatureDomain = "BIFROEST-ASCIICAST-SIGNATURE/v1\x00"
)

type SessionRecordingCastSignature struct {
	Schema      string     `json:"schema"`
	RecordingId string     `json:"recordingId"`
	ProducerId  ProducerId `json:"producerId"`
	Digest      string     `json:"digest"`
	PublicKey   []byte     `json:"publicKey"`
	Signature   []byte     `json:"signature"`
}

type sessionRecordingCastSignatureContent struct {
	Schema      string     `json:"schema"`
	RecordingId string     `json:"recordingId"`
	ProducerId  ProducerId `json:"producerId"`
	Digest      string     `json:"digest"`
	PublicKey   []byte     `json:"publicKey"`
}

// NewSessionRecordingCastSignature creates a signature for one validated cast
// digest without exposing a general-purpose signing operation.
func (this *Identity) NewSessionRecordingCastSignature(recordingId, digest string) (SessionRecordingCastSignature, error) {
	if this == nil || this.PublicKey() == nil {
		return SessionRecordingCastSignature{}, errors.System.Newf("nil audit identity signer")
	}
	content := sessionRecordingCastSignatureContent{
		Schema:      SessionRecordingCastSignatureSchema,
		RecordingId: recordingId,
		ProducerId:  this.ProducerId(),
		Digest:      digest,
		PublicKey:   this.PublicKey().Marshal(),
	}
	if err := validateSessionRecordingCastSignatureContent(content); err != nil {
		return SessionRecordingCastSignature{}, err
	}
	payload, err := json.Marshal(content)
	if err != nil {
		return SessionRecordingCastSignature{}, errors.System.Newf("cannot encode session recording signature metadata: %w", err)
	}
	signature, err := this.sign(append([]byte(sessionRecordingCastSignatureDomain), payload...))
	if err != nil {
		return SessionRecordingCastSignature{}, err
	}
	return SessionRecordingCastSignature{
		Schema:      content.Schema,
		RecordingId: content.RecordingId,
		ProducerId:  content.ProducerId,
		Digest:      content.Digest,
		PublicKey:   content.PublicKey,
		Signature:   signature,
	}, nil
}

// VerifySessionRecordingCastSignature verifies internal consistency and the
// signature. Trust in the returned public key must be established separately.
func VerifySessionRecordingCastSignature(value SessionRecordingCastSignature) (bfcrypto.PublicKey, error) {
	content := sessionRecordingCastSignatureContent{
		Schema:      value.Schema,
		RecordingId: value.RecordingId,
		ProducerId:  value.ProducerId,
		Digest:      value.Digest,
		PublicKey:   value.PublicKey,
	}
	if err := validateSessionRecordingCastSignatureContent(content); err != nil {
		return nil, err
	}
	publicKey, err := bfcrypto.ParsePublicKeyBytes(value.PublicKey)
	if err != nil {
		return nil, errors.System.Newf("cannot parse session recording public key: %w", err)
	}
	if !bytes.Equal(publicKey.Marshal(), value.PublicKey) {
		return nil, errors.System.Newf("session recording public key is not canonical")
	}
	ed25519PublicKey, ok := publicKey.ToSdk().(ed25519.PublicKey)
	if !ok || len(ed25519PublicKey) != ed25519.PublicKeySize {
		return nil, errors.System.Newf("session recording public key is not Ed25519")
	}
	if ProducerId(sha256.Sum256(value.PublicKey)) != value.ProducerId {
		return nil, errors.System.Newf("session recording public key does not match its producer ID")
	}
	payload, err := json.Marshal(content)
	if err != nil {
		return nil, errors.System.Newf("cannot encode session recording signature metadata: %w", err)
	}
	message := append([]byte(sessionRecordingCastSignatureDomain), payload...)
	if len(value.Signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519PublicKey, message, value.Signature) {
		return nil, errors.System.Newf("illegal session recording signature")
	}
	return publicKey, nil
}

func validateSessionRecordingCastSignatureContent(value sessionRecordingCastSignatureContent) error {
	if value.Schema != SessionRecordingCastSignatureSchema {
		return errors.System.Newf("unsupported session recording signature schema %q", value.Schema)
	}
	recordingId, err := uuid.Parse(value.RecordingId)
	if err != nil || recordingId == uuid.Nil || recordingId.Version() != 4 || recordingId.Variant() != uuid.RFC4122 || recordingId.String() != value.RecordingId {
		return errors.System.Newf("illegal session recording ID %q", value.RecordingId)
	}
	if value.ProducerId.IsZero() {
		return errors.System.Newf("session recording producer ID is empty")
	}
	if len(value.Digest) != sha256.Size*2 {
		return errors.System.Newf("illegal session recording digest length: %d", len(value.Digest))
	}
	digest, err := hex.DecodeString(value.Digest)
	if err != nil || hex.EncodeToString(digest) != value.Digest {
		return errors.System.Newf("illegal session recording digest %q", value.Digest)
	}
	if len(value.PublicKey) == 0 {
		return errors.System.Newf("session recording public key is empty")
	}
	return nil
}
