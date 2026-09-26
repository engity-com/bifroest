package nativeformat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestNativePayloadCompressesBeforeIndependentAgeEncryption(t *testing.T) {
	limits := PayloadLimits{MaxDecoded: MaxAuditEventPayload, MaxStored: MaxAuditRecordPayload}
	plaintext, err := Marshal(map[uint64]any{1: "sensitive-flow", 2: "connection-id"}, limits.MaxDecoded)
	require.NoError(t, err)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	identity, err := bfcrypto.PrivateKeyFromSdk(privateKey)
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(identity.PublicKey().ToSsh())
	require.NoError(t, err)
	identities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{identity})
	require.NoError(t, err)

	plainFrame, err := EncodeStoredPayload(plaintext, nil, limits)
	require.NoError(t, err)
	decoded, err := DecodeStoredPayload(plainFrame, nil, "", limits)
	require.NoError(t, err)
	require.Equal(t, plaintext, decoded)
	first, err := EncodeStoredPayload(plaintext, recipient, limits)
	require.NoError(t, err)
	second, err := EncodeStoredPayload(plaintext, recipient, limits)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	require.NotContains(t, first, []byte("sensitive-flow"))
	for _, stored := range [][]byte{first, second} {
		decoded, err := DecodeStoredPayload(stored, identities, recipient.Fingerprint(), limits)
		require.NoError(t, err)
		require.Equal(t, plaintext, decoded)
		_, err = DecodeZstdFrame(stored, limits)
		require.Error(t, err, "ciphertext must not be treated as a Zstd frame")
	}

	_, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherKey, err := bfcrypto.PrivateKeyFromSdk(otherPrivateKey)
	require.NoError(t, err)
	otherRecipient, err := bfcrypto.NewAgeSshRecipient(otherKey.PublicKey().ToSsh())
	require.NoError(t, err)
	otherIdentities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{otherKey})
	require.NoError(t, err)
	bothIdentities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{identity, otherKey})
	require.NoError(t, err)
	for _, attempt := range []struct {
		name        string
		stored      []byte
		identities  *bfcrypto.AgeSshIdentities
		fingerprint string
	}{
		{"missing identity", first, nil, recipient.Fingerprint()},
		{"wrong key", first, otherIdentities, recipient.Fingerprint()},
		{"wrong fingerprint", first, identities, otherRecipient.Fingerprint()},
		{"no identity fallback", first, bothIdentities, otherRecipient.Fingerprint()},
		{"torn ciphertext", first[:len(first)-1], identities, recipient.Fingerprint()},
		{"trailing ciphertext", append(bytes.Clone(first), []byte("trailing")...), identities, recipient.Fingerprint()},
		{"second age message", append(bytes.Clone(first), second...), identities, recipient.Fingerprint()},
		{"changed ciphertext", func() []byte {
			v := bytes.Clone(first)
			v[len(v)-1] ^= 1
			return v
		}(), identities, recipient.Fingerprint()},
		{"oversized ciphertext", bytes.Repeat([]byte{1}, limits.MaxStored+1), identities, recipient.Fingerprint()},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			decoded, err := DecodeStoredPayload(attempt.stored, attempt.identities, attempt.fingerprint, limits)
			require.Error(t, err)
			require.Nil(t, decoded)
		})
	}
	_, err = EncodeStoredPayload(plaintext, recipient, PayloadLimits{MaxDecoded: limits.MaxDecoded, MaxStored: len(first) - 1})
	require.Error(t, err)
}

func TestNativeAgeAuthenticatesMultiChunkCiphertext(t *testing.T) {
	limits := PayloadLimits{MaxDecoded: MaxRecordingDecodedChunk, MaxStored: MaxRecordingChunkPayload}
	content := make([]byte, 128<<10)
	_, err := rand.Read(content)
	require.NoError(t, err)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := bfcrypto.PrivateKeyFromSdk(privateKey)
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(key.PublicKey().ToSsh())
	require.NoError(t, err)
	identities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{key})
	require.NoError(t, err)
	stored, err := EncodeStoredPayload(content, recipient, limits)
	require.NoError(t, err)
	require.Greater(t, len(stored), 64<<10)
	decoded, err := DecodeStoredPayload(stored, identities, recipient.Fingerprint(), limits)
	require.NoError(t, err)
	require.Equal(t, content, decoded)
	tampered := bytes.Clone(stored)
	tampered[len(tampered)/2] ^= 1
	decoded, err = DecodeStoredPayload(tampered, identities, recipient.Fingerprint(), limits)
	require.Error(t, err)
	require.Nil(t, decoded)
}
