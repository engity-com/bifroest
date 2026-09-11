package crypto

import (
	"crypto/dsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	goos "os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestEnsureKeyFileCreatesOneCompleteKeyConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	requirement := &KeyRequirement{Type: KeyTypeEd25519}
	const workers = 16
	fingerprints := make(chan string, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			key, err := EnsureKeyFile(path, requirement, nil)
			if err != nil {
				errors <- err
				return
			}
			fingerprints <- ssh.FingerprintSHA256(key.ToSsh().PublicKey())
		}()
	}
	wait.Wait()
	close(fingerprints)
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	var expected string
	for fingerprint := range fingerprints {
		if expected == "" {
			expected = fingerprint
		}
		require.Equal(t, expected, fingerprint)
	}
	require.NotEmpty(t, expected)
	_, err := EnsureKeyFile(path, nil, nil)
	require.NoError(t, err)
}

func TestEnsureKeyFileRejectsUnsupportedDsaWithoutPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	private := &dsa.PrivateKey{}
	require.NoError(t, dsa.GenerateParameters(&private.Parameters, rand.Reader, dsa.L1024N160))
	require.NoError(t, dsa.GenerateKey(private, rand.Reader))
	der, err := asn1.Marshal(struct {
		Version       int
		P, Q, G, Y, X *big.Int
	}{0, private.P, private.Q, private.G, private.Y, private.X})
	require.NoError(t, err)
	require.NoError(t, goos.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: der}), 0400))

	_, err = EnsureKeyFile(path, nil, nil)
	require.ErrorContains(t, err, "unsupported key type")
}
