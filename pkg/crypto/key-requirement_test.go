package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// Keep real generation/serialization at production defaults covered once, rather
// than generating unrelated host keys in every service state test.
func TestKeyRequirementGenerateKeyDefaults(t *testing.T) {
	for _, kind := range []KeyType{KeyTypeRsa, KeyTypeEcdsa, KeyTypeEd25519} {
		t.Run(kind.String(), func(t *testing.T) {
			key, err := (KeyRequirement{Type: kind}).GenerateKey(nil)
			require.NoError(t, err)
			switch kind {
			case KeyTypeRsa:
				sdk := key.ToSdk().(*rsa.PrivateKey)
				require.Equal(t, 4096, sdk.N.BitLen())
				require.NoError(t, sdk.Validate())
			case KeyTypeEcdsa:
				require.Equal(t, elliptic.P521(), key.ToSdk().(*ecdsa.PrivateKey).Curve)
			case KeyTypeEd25519:
				require.Len(t, key.ToSdk().(ed25519.PrivateKey), ed25519.PrivateKeySize)
			}
			var encoded bytes.Buffer
			require.NoError(t, WriteSshPrivateKey(key, &encoded))
			parsed, err := ParsePrivateKeyBytes(encoded.Bytes())
			require.NoError(t, err)
			require.True(t, key.PublicKey().IsEqualTo(parsed.PublicKey()))
		})
	}
}
