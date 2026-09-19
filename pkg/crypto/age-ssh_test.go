package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestAgeSshEd25519RoundTripAndAuthentication(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	sdkKey := ed25519.NewKeyFromSeed(seed)
	key, err := PrivateKeyFromSdk(sdkKey)
	require.NoError(t, err)
	recipient, err := NewAgeSshRecipient(key.PublicKey().ToSsh())
	require.NoError(t, err)
	require.NotEmpty(t, recipient.Fingerprint())
	identities, err := NewAgeSshIdentities([]PrivateKey{key})
	require.NoError(t, err)

	first := encryptAgeSshTestMessage(t, recipient, []byte("secret recording"))
	second := encryptAgeSshTestMessage(t, recipient, []byte("secret recording"))
	require.NotEqual(t, first, second)
	require.Equal(t, []byte("secret recording"), decryptAgeSshTestMessage(t, identities, first))
	require.Equal(t, []byte("secret recording"), decryptAgeSshTestMessage(t, identities, second))
	targeted, err := identities.DecryptForFingerprint(bytes.NewReader(first), recipient.Fingerprint())
	require.NoError(t, err)
	targetedPlaintext, err := io.ReadAll(targeted)
	require.NoError(t, err)
	require.Equal(t, []byte("secret recording"), targetedPlaintext)

	tampered := append([]byte(nil), first...)
	tampered[len(tampered)-1] ^= 1
	reader, err := identities.Decrypt(bytes.NewReader(tampered))
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	require.Error(t, err)
	require.True(t, bferrors.System.IsErr(err))

	otherSdkKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xff}, ed25519.SeedSize))
	otherKey, err := PrivateKeyFromSdk(otherSdkKey)
	require.NoError(t, err)
	otherIdentities, err := NewAgeSshIdentities([]PrivateKey{otherKey})
	require.NoError(t, err)
	_, err = otherIdentities.Decrypt(bytes.NewReader(first))
	require.True(t, bferrors.Config.IsErr(err))
	_, err = otherIdentities.DecryptForFingerprint(bytes.NewReader(first), recipient.Fingerprint())
	require.True(t, bferrors.Config.IsErr(err))
	otherRecipient, err := NewAgeSshRecipient(otherKey.PublicKey().ToSsh())
	require.NoError(t, err)
	_, err = otherIdentities.DecryptForFingerprint(bytes.NewReader(first), otherRecipient.Fingerprint())
	require.True(t, bferrors.System.IsErr(err))
}

func TestAgeSshAcceptsPointerEd25519AndRsaIdentities(t *testing.T) {
	ed25519Key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ed25519Pointer, err := PrivateKeyFromSdk(&ed25519Key)
	require.NoError(t, err)
	ed25519Identities, err := NewAgeSshIdentities([]PrivateKey{ed25519Pointer})
	require.NoError(t, err)
	ed25519Recipient, err := NewAgeSshRecipient(ed25519Pointer.PublicKey().ToSsh())
	require.NoError(t, err)
	require.Equal(t, []byte("ed25519"), decryptAgeSshTestMessage(t, ed25519Identities, encryptAgeSshTestMessage(t, ed25519Recipient, []byte("ed25519"))))

	rsaSdkKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKey, err := PrivateKeyFromSdk(rsaSdkKey)
	require.NoError(t, err)
	rsaRecipient, err := NewAgeSshRecipient(rsaKey.PublicKey().ToSsh())
	require.NoError(t, err)
	rsaIdentities, err := NewAgeSshIdentities([]PrivateKey{rsaKey})
	require.NoError(t, err)
	require.Equal(t, []byte("rsa"), decryptAgeSshTestMessage(t, rsaIdentities, encryptAgeSshTestMessage(t, rsaRecipient, []byte("rsa"))))
}

func TestAgeSshRejectsNilValues(t *testing.T) {
	_, err := NewAgeSshRecipient(nil)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	_, err = NewAgeSshIdentities(nil)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	_, err = NewAgeSshIdentities([]PrivateKey{nil})
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	var recipient *AgeSshRecipient
	_, err = recipient.Encrypt(io.Discard)
	require.True(t, bferrors.System.IsErr(err))
}

func encryptAgeSshTestMessage(t *testing.T, recipient *AgeSshRecipient, plaintext []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := recipient.Encrypt(&output)
	require.NoError(t, err)
	written, err := writer.Write(plaintext)
	require.NoError(t, err)
	require.Equal(t, len(plaintext), written)
	require.NoError(t, writer.Close())
	return output.Bytes()
}

func decryptAgeSshTestMessage(t *testing.T, identities *AgeSshIdentities, ciphertext []byte) []byte {
	t.Helper()
	reader, err := identities.Decrypt(bytes.NewReader(ciphertext))
	require.NoError(t, err)
	plaintext, err := io.ReadAll(reader)
	require.NoError(t, err)
	return plaintext
}
