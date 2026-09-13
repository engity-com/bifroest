package audit

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestEnsureIdentityDoesNothingWhenDisabled(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, false)

	identity, err := EnsureIdentity(&conf)

	require.NoError(t, err)
	require.Nil(t, identity)
	require.NoFileExists(t, conf.IdentityFile)
	require.NoDirExists(t, conf.Journal.Directory)
}

func TestEnsureIdentityCreatesAndReusesDedicatedKey(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)

	first, err := EnsureIdentity(&conf)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.False(t, first.ProducerId().IsZero())
	require.Equal(t, gossh.KeyAlgoED25519, first.PublicKey().Type())
	require.Equal(t, gossh.FingerprintSHA256(first.PublicKey().ToSsh()), first.Fingerprint())
	require.FileExists(t, conf.IdentityFile)
	require.NoDirExists(t, conf.Journal.Directory)

	require.NoError(t, os.MkdirAll(conf.Journal.Directory, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(conf.Journal.Directory, "existing-segment"), []byte("history"), 0600))
	second, err := EnsureIdentity(&conf)
	require.NoError(t, err)
	require.Equal(t, first.ProducerId(), second.ProducerId())
	require.Equal(t, first.Fingerprint(), second.Fingerprint())
}

func TestEnsureIdentityCreatesKeyForEmptyJournal(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)
	require.NoError(t, os.MkdirAll(conf.Journal.Directory, 0700))

	identity, err := EnsureIdentity(&conf)

	require.NoError(t, err)
	require.NotNil(t, identity)
	require.FileExists(t, conf.IdentityFile)
}

func TestEnsureIdentityIgnoresPersistentJournalLock(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)
	require.NoError(t, os.MkdirAll(conf.Journal.Directory, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(conf.Journal.Directory, journalLockFileName), nil, 0600))

	identity, err := EnsureIdentity(&conf)

	require.NoError(t, err)
	require.NotNil(t, identity)
	require.FileExists(t, conf.IdentityFile)
}

func TestEnsureIdentityRejectsMissingKeyForExistingJournal(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)
	require.NoError(t, os.MkdirAll(conf.Journal.Directory, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(conf.Journal.Directory, "existing-segment"), []byte("history"), 0600))

	identity, err := EnsureIdentity(&conf)

	require.Nil(t, identity)
	require.ErrorContains(t, err, "is missing while journal")
	require.True(t, berrors.Config.IsErr(err))
	require.NoFileExists(t, conf.IdentityFile)
}

func TestEnsureIdentityDoesNotReplaceInvalidKey(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)
	expected := []byte("invalid")
	require.NoError(t, os.WriteFile(conf.IdentityFile, expected, 0600))

	identity, err := EnsureIdentity(&conf)

	require.Nil(t, identity)
	require.Error(t, err)
	require.True(t, berrors.Config.IsErr(err))
	actual, readErr := os.ReadFile(conf.IdentityFile)
	require.NoError(t, readErr)
	require.Equal(t, expected, actual)
}

func TestEnsureIdentityRejectsNonRegularAndOversizedKeyFiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, string)
		error   string
	}{
		{"directory", func(t *testing.T, path string) { require.NoError(t, os.Mkdir(path, 0700)) }, "not a regular file"},
		{"oversized", func(t *testing.T, path string) {
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
			require.NoError(t, err)
			require.NoError(t, file.Truncate(maxAuditIdentityFileSize+1))
			require.NoError(t, file.Close())
		}, "exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := auditIdentityTestConfiguration(t.TempDir(), true)
			tc.prepare(t, conf.IdentityFile)

			identity, err := EnsureIdentity(&conf)

			require.Nil(t, identity)
			require.ErrorContains(t, err, tc.error)
		})
	}
}

func TestEnsureIdentityDoesNotReplaceWrongKeyType(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)
	_, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEcdsa}).CreateFile(nil, conf.IdentityFile)
	require.NoError(t, err)
	expected, err := os.ReadFile(conf.IdentityFile)
	require.NoError(t, err)

	identity, err := EnsureIdentity(&conf)

	require.Nil(t, identity)
	require.ErrorContains(t, err, "instead of Ed25519")
	require.True(t, berrors.Config.IsErr(err))
	actual, readErr := os.ReadFile(conf.IdentityFile)
	require.NoError(t, readErr)
	require.Equal(t, expected, actual)
}

func TestIdentityRejectsReusedHostKey(t *testing.T) {
	privateKey, err := auditIdentityKeyRequirement.GenerateKey(nil)
	require.NoError(t, err)
	identity, err := NewIdentity(privateKey)
	require.NoError(t, err)
	other, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).GenerateKey(nil)
	require.NoError(t, err)

	require.NoError(t, identity.ValidateDedicatedFrom([]bfcrypto.PrivateKey{nil, other}))
	err = identity.ValidateDedicatedFrom([]bfcrypto.PrivateKey{privateKey})
	require.ErrorContains(t, err, "must not reuse")
	require.True(t, berrors.Config.IsErr(err))
}

func TestProducerIdTextRoundTrip(t *testing.T) {
	privateKey, err := auditIdentityKeyRequirement.GenerateKey(nil)
	require.NoError(t, err)
	identity, err := NewIdentity(privateKey)
	require.NoError(t, err)
	expected := identity.ProducerId()
	expectedDigest := sha256.Sum256(identity.PublicKey().ToSsh().Marshal())
	require.Equal(t, ProducerId(expectedDigest), expected)

	raw, err := expected.MarshalText()
	require.NoError(t, err)
	require.Len(t, raw, 64)
	var actual ProducerId
	require.NoError(t, actual.UnmarshalText(raw))
	require.Equal(t, expected, actual)
	require.Equal(t, string(raw), actual.String())

	err = actual.UnmarshalText([]byte("too-short"))
	require.Error(t, err)
	require.True(t, berrors.Config.IsErr(err))
	err = actual.UnmarshalText([]byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))
	require.Error(t, err)
	require.True(t, berrors.Config.IsErr(err))
}

func auditIdentityTestConfiguration(directory string, enabled bool) configuration.Auditlog {
	return configuration.Auditlog{
		Enabled:      enabled,
		IdentityFile: filepath.Join(directory, "auditlog-key"),
		Journal: configuration.AuditlogJournal{
			Directory: filepath.Join(directory, "journal"),
		},
	}
}
