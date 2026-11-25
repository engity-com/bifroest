package testkeys_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/internal/testkeys"
)

func TestPublicFixturesAreIndependent(t *testing.T) {
	for _, fixture := range []struct {
		name string
		pem  string
	}{
		{"Ed25519", testkeys.Ed25519},
		{"OtherEd25519", testkeys.OtherEd25519},
		{"RSA2048", testkeys.RSA2048},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			for range 4 {
				t.Run("caller", func(t *testing.T) {
					t.Parallel()
					input := []byte(fixture.pem)
					before := bytes.Clone(input)
					first, err := ssh.ParseRawPrivateKey(input)
					require.NoError(t, err)
					expected, err := ssh.ParseRawPrivateKey([]byte(fixture.pem))
					require.NoError(t, err)
					require.Equal(t, before, input, "parsing must not modify fixture bytes")
					switch key := first.(type) {
					case *ed25519.PrivateKey:
						(*key)[0] ^= 1
					case *rsa.PrivateKey:
						require.Equal(t, 2048, key.N.BitLen())
						key.D.SetInt64(0)
						key.Primes[0].SetInt64(0)
					default:
						t.Fatalf("unexpected fixture type %T", first)
					}
					input[0] ^= 1
					actual, err := ssh.ParseRawPrivateKey([]byte(fixture.pem))
					require.NoError(t, err)
					require.Equal(t, expected, actual, "callers must receive independent parsed keys")
					require.NotEqual(t, first, actual)
					require.Equal(t, before, []byte(fixture.pem), "caller mutations must not change the fixture")
				})
			}
		})
	}
}

func TestPublicDSAFixtureIsValidButUnsupported(t *testing.T) {
	block, rest := pem.Decode([]byte(testkeys.DSA1024))
	require.NotNil(t, block)
	require.Empty(t, rest)
	require.Equal(t, "DSA PRIVATE KEY", block.Type)
	var key struct {
		Version       int
		P, Q, G, Y, X *big.Int
	}
	rest, err := asn1.Unmarshal(block.Bytes, &key)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Zero(t, key.Version)
	require.Equal(t, 1024, key.P.BitLen())
	require.Equal(t, 160, key.Q.BitLen())
	require.Positive(t, key.X.Sign())
	require.Negative(t, key.X.Cmp(key.Q))
	require.Equal(t, key.Y, new(big.Int).Exp(key.G, key.X, key.P))
	_, err = ssh.ParseRawPrivateKey([]byte(testkeys.DSA1024))
	require.ErrorContains(t, err, "unsupported key type")
}

func TestPublicEncryptedFixtureUsesRealKDF(t *testing.T) {
	input := []byte(testkeys.EncryptedEd25519)
	before := bytes.Clone(input)
	block, rest := pem.Decode(input)
	require.NotNil(t, block)
	require.Empty(t, rest)
	require.Equal(t, "OPENSSH PRIVATE KEY", block.Type)
	const magic = "openssh-key-v1\x00"
	require.True(t, bytes.HasPrefix(block.Bytes, []byte(magic)))
	var envelope struct {
		Cipher, KDF, Options string
		Keys                 uint32
		Public, Private      []byte
	}
	require.NoError(t, ssh.Unmarshal(block.Bytes[len(magic):], &envelope))
	require.Equal(t, "aes256-ctr", envelope.Cipher)
	require.Equal(t, "bcrypt", envelope.KDF)
	var options struct {
		Salt   []byte
		Rounds uint32
	}
	require.NoError(t, ssh.Unmarshal([]byte(envelope.Options), &options))
	require.Len(t, options.Salt, 16)
	require.Equal(t, uint32(16), options.Rounds, "retain the standard OpenSSH bcrypt work factor")

	expected, err := ssh.ParseRawPrivateKey([]byte(testkeys.Ed25519))
	require.NoError(t, err)
	actual, err := ssh.ParseRawPrivateKeyWithPassphrase(input, []byte(testkeys.Passphrase))
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	_, err = ssh.ParseRawPrivateKeyWithPassphrase(input, []byte("wrong PUBLIC fixture passphrase"))
	require.ErrorIs(t, err, x509.IncorrectPasswordError)
	_, err = ssh.ParseRawPrivateKey(input)
	var missing *ssh.PassphraseMissingError
	require.ErrorAs(t, err, &missing)
	require.Equal(t, before, input, "successful and failed KDF imports must preserve fixture bytes")
}
