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
	require.NoDirExists(t, conf.Directory)
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
	require.NoDirExists(t, conf.Directory)

	require.NoError(t, os.MkdirAll(conf.Directory, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(conf.Directory, "existing-segment"), []byte("history"), 0600))
	second, err := EnsureIdentity(&conf)
	require.NoError(t, err)
	require.Equal(t, first.ProducerId(), second.ProducerId())
	require.Equal(t, first.Fingerprint(), second.Fingerprint())
}

func TestEnsureIdentityRecordingOnlyDoesNotCreateJournal(t *testing.T) {
	conf := auditIdentityTestConfiguration(t.TempDir(), false)
	conf.Recording.Enabled = true
	conf.Recording.Directory = filepath.Join(filepath.Dir(conf.IdentityFile), "recordings")
	first, err := EnsureIdentity(&conf)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.FileExists(t, conf.IdentityFile)
	require.NoDirExists(t, conf.Recording.Directory)
	require.NoDirExists(t, conf.Directory)

	conf.Directory = ""
	second, err := EnsureIdentity(&conf)
	require.NoError(t, err)
	require.Equal(t, first.ProducerId(), second.ProducerId())
}

func TestEnsureIdentityRecordingOnlyRejectsMissingKeyWithEvidence(t *testing.T) {
	for _, kind := range []string{"journal", "journal workspace", "recording"} {
		t.Run(kind, func(t *testing.T) {
			conf := auditIdentityTestConfiguration(t.TempDir(), false)
			conf.Recording.Enabled = true
			conf.Recording.Directory = filepath.Join(filepath.Dir(conf.IdentityFile), "recordings")
			path := conf.Directory
			switch kind {
			case "recording":
				path = conf.Recording.Directory
			case "journal workspace":
				path = filepath.Join(conf.Directory, journalWorkDirectoryName)
				require.NoError(t, os.Mkdir(conf.Directory, 0700))
			}
			require.NoError(t, os.Mkdir(path, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(path, "existing-state"), []byte("signed evidence"), 0600))
			identity, err := EnsureIdentity(&conf)
			require.Nil(t, identity)
			require.ErrorContains(t, err, "is missing while")
			require.True(t, berrors.Config.IsErr(err))
			require.NoFileExists(t, conf.IdentityFile)
		})
	}
}

func TestEnsureIdentityRecordingOnlySharedJournal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prepare   func(*testing.T, configuration.Auditlog, *configuration.Auditlog)
		wantError bool
	}{
		{"other journal history", nil, false},
		{"symlink to other journal", func(t *testing.T, owner configuration.Auditlog, recording *configuration.Auditlog) {
			alias := filepath.Join(filepath.Dir(owner.Directory), "journal-alias")
			if err := os.Symlink(owner.Directory, alias); err != nil {
				t.Skipf("journal symlink unavailable: %v", err)
			}
			recording.Directory = alias
		}, false},
		{"other journal delivery state", func(t *testing.T, owner configuration.Auditlog, recording *configuration.Auditlog) {
			key, err := LoadExistingIdentityPublicKey(owner.IdentityFile)
			require.NoError(t, err)
			path := filepath.Join(owner.Directory, remoteDeliveryStateDirectoryName, newProducerId(key.Marshal()).String())
			require.NoError(t, os.MkdirAll(path, 0700))
		}, false},
		{"old own journal history", func(t *testing.T, owner configuration.Auditlog, recording *configuration.Auditlog) {
			other, err := auditIdentityKeyRequirement.GenerateKey(nil)
			require.NoError(t, err)
			id, err := NewIdentity(other)
			require.NoError(t, err)
			require.NoError(t, os.Mkdir(filepath.Join(owner.Directory, id.ProducerId().String()), 0700))
		}, true},
		{"old own delivery state", func(t *testing.T, owner configuration.Auditlog, recording *configuration.Auditlog) {
			path := filepath.Join(owner.Directory, remoteDeliveryStateDirectoryName, "old-producer")
			require.NoError(t, os.MkdirAll(path, 0700))
		}, true},
		{"old own workspace", func(t *testing.T, owner configuration.Auditlog, recording *configuration.Auditlog) {
			path := filepath.Join(owner.Directory, journalWorkDirectoryName)
			require.NoError(t, os.Mkdir(path, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(path, "state"), nil, 0600))
		}, true},
		{"existing recording", func(t *testing.T, owner configuration.Auditlog, recording *configuration.Auditlog) {
			require.NoError(t, os.Mkdir(recording.Recording.Directory, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(recording.Recording.Directory, "sealed"), nil, 0600))
		}, true},
		{"missing owner key", func(t *testing.T, owner configuration.Auditlog, recording *configuration.Auditlog) {
			require.NoError(t, os.Remove(owner.IdentityFile))
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			owner := auditIdentityTestConfiguration(root, true)
			owner.Name = "owner"
			owner.IdentityFile = filepath.Join(root, "owner-key")
			ownerIdentity, err := EnsureIdentity(&owner)
			require.NoError(t, err)
			require.NoError(t, os.Mkdir(owner.Directory, 0700))
			require.NoError(t, os.Mkdir(filepath.Join(owner.Directory, ownerIdentity.ProducerId().String()), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(owner.Directory, ownerIdentity.ProducerId().String(), "segment"), nil, 0600))
			recording := auditIdentityTestConfiguration(root, false)
			recording.Name = "recording"
			require.NoError(t, recording.Recording.SetDefaults())
			recording.Recording.Enabled = true
			recording.Recording.Directory = filepath.Join(root, "recordings")
			if tc.prepare != nil {
				tc.prepare(t, owner, &recording)
			}
			logs := configuration.Auditlogs{owner, recording}
			require.NoError(t, logs.Validate())
			// A direct call without the complete configuration must remain fail-closed.
			plain, err := EnsureIdentity(&recording)
			require.Nil(t, plain)
			require.ErrorContains(t, err, "is missing while journal")
			identity, err := EnsureIdentityWithAuditlogs(&recording, logs)
			if tc.wantError {
				require.Nil(t, identity)
				require.Error(t, err)
				require.NoFileExists(t, recording.IdentityFile)
			} else {
				require.NoError(t, err)
				require.NotNil(t, identity)
				require.NotEqual(t, ownerIdentity.ProducerId(), identity.ProducerId())
				require.NoDirExists(t, recording.Recording.Directory)
			}
		})
	}
}

func TestEnsureIdentityCreatesKeyForEmptyJournal(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)
	require.NoError(t, os.MkdirAll(conf.Directory, 0700))

	identity, err := EnsureIdentity(&conf)

	require.NoError(t, err)
	require.NotNil(t, identity)
	require.FileExists(t, conf.IdentityFile)
}

func TestEnsureIdentityIgnoresPersistentJournalLock(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)
	require.NoError(t, os.MkdirAll(conf.Directory, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(conf.Directory, journalLockFileName), nil, 0600))

	identity, err := EnsureIdentity(&conf)

	require.NoError(t, err)
	require.NotNil(t, identity)
	require.FileExists(t, conf.IdentityFile)
}

func TestEnsureIdentityRejectsMissingKeyForExistingJournal(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(directory, true)
	require.NoError(t, os.MkdirAll(conf.Directory, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(conf.Directory, "existing-segment"), []byte("history"), 0600))

	identity, err := EnsureIdentity(&conf)

	require.Nil(t, identity)
	require.ErrorContains(t, err, "is missing while journal")
	require.True(t, berrors.Config.IsErr(err))
	require.NoFileExists(t, conf.IdentityFile)
}

func TestEnsureIdentityRejectsMissingKeyForRecordingState(t *testing.T) {
	for _, journalExists := range []bool{false, true} {
		for _, recordingEnabled := range []bool{false, true} {
			t.Run(map[bool]string{false: "missing journal", true: "empty journal"}[journalExists]+map[bool]string{false: "/disabled Recording", true: "/enabled Recording"}[recordingEnabled], func(t *testing.T) {
				root := t.TempDir()
				conf := auditIdentityTestConfiguration(root, true)
				conf.Recording.Enabled = recordingEnabled
				conf.Recording.Directory = filepath.Join(root, "recordings")
				if journalExists {
					require.NoError(t, os.Mkdir(conf.Directory, 0700))
				}
				require.NoError(t, os.Mkdir(conf.Recording.Directory, 0700))
				state := filepath.Join(conf.Recording.Directory, "sealed")
				require.NoError(t, os.Mkdir(state, 0700))

				identity, err := EnsureIdentity(&conf)
				require.Nil(t, identity)
				require.ErrorContains(t, err, "Recording directory")
				require.True(t, berrors.Config.IsErr(err))
				require.NoFileExists(t, conf.IdentityFile)
				require.DirExists(t, state)
			})
		}
	}
}

func TestLoadExistingIdentityPublicKeyIsReadOnly(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	key, err := LoadExistingIdentityPublicKey(missing)
	require.NoError(t, err)
	require.Nil(t, key)
	require.NoFileExists(t, missing)

	path := filepath.Join(root, "disabled-key")
	privateKey, err := auditIdentityKeyRequirement.CreateFile(nil, path)
	require.NoError(t, err)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	key, err = LoadExistingIdentityPublicKey(path)
	require.NoError(t, err)
	require.True(t, key.IsEqualTo(privateKey.PublicKey()))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)

	invalid := filepath.Join(root, "invalid")
	require.NoError(t, os.WriteFile(invalid, []byte("not a key"), 0600))
	key, err = LoadExistingIdentityPublicKey(invalid)
	require.Nil(t, key)
	require.ErrorContains(t, err, "cannot load audit identity file")
}

func TestEnsureIdentityAllowsEmptyRecordingDirectory(t *testing.T) {
	conf := auditIdentityTestConfiguration(t.TempDir(), true)
	conf.Recording.Enabled = true
	conf.Recording.Directory = filepath.Join(filepath.Dir(conf.IdentityFile), "recordings")
	require.NoError(t, os.Mkdir(conf.Recording.Directory, 0700))

	identity, err := EnsureIdentity(&conf)
	require.NoError(t, err)
	require.NotNil(t, identity)
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

func TestIdentityRejectsReusedSftpPublicKey(t *testing.T) {
	key, err := auditIdentityKeyRequirement.GenerateKey(nil)
	require.NoError(t, err)
	identity, err := NewIdentity(key)
	require.NoError(t, err)
	other, err := auditIdentityKeyRequirement.GenerateKey(nil)
	require.NoError(t, err)

	require.NoError(t, identity.ValidateDedicatedFromPublicKeys([]bfcrypto.PublicKey{nil, other.PublicKey()}))
	err = identity.ValidateDedicatedFromPublicKeys([]bfcrypto.PublicKey{key.PublicKey()})
	require.ErrorContains(t, err, "SFTP target identity")
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
		Directory:    filepath.Join(directory, "journal"),
	}
}
