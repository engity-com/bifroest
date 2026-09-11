package audit

import (
	"bytes"
	"crypto/ed25519"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

type journalIdentity interface {
	ProducerId() ProducerId
	journalPublicKey() []byte
	verify([]byte, []byte) error
}

type journalPublicIdentity struct {
	producerId ProducerId
	encodedKey []byte
	publicKey  ed25519.PublicKey
}

func newJournalPublicIdentity(producerId ProducerId, encodedKey []byte) (*journalPublicIdentity, error) {
	if producerId.IsZero() || newProducerId(encodedKey) != producerId {
		return nil, errors.System.Newf("audit public key does not match producer %s", producerId)
	}
	parsed, err := bfcrypto.ParsePublicKeyBytes(encodedKey)
	if err != nil {
		return nil, errors.System.Newf("cannot parse audit public key: %w", err)
	}
	publicKey, ok := parsed.ToSdk().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || !bytes.Equal(parsed.Marshal(), encodedKey) {
		return nil, errors.System.Newf("audit producer %s does not use a canonical Ed25519 public key", producerId)
	}
	return &journalPublicIdentity{
		producerId: producerId,
		encodedKey: append([]byte(nil), encodedKey...),
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
	}, nil
}

func (this *journalPublicIdentity) ProducerId() ProducerId {
	return this.producerId
}

func (this *journalPublicIdentity) journalPublicKey() []byte {
	return this.encodedKey
}

func (this *journalPublicIdentity) verify(message, signature []byte) error {
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(this.publicKey, message, signature) {
		return errors.System.Newf("illegal audit signature")
	}
	return nil
}
