package crypto

import (
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
