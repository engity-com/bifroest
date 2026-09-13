//go:build unix

package main

import (
	goos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestLoadAuditPrivateKeyRejectsInsecureMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-key")
	require.NoError(t, goos.WriteFile(path, []byte("not relevant"), 0644))
	_, err := loadAuditPrivateKey(path)
	require.ErrorContains(t, err, "accessible by group or others")
}

func TestLoadAuditPrivateKeyRejectsSymlinkAndHardLink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-key")
	_, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(nil, target)
	require.NoError(t, err)
	symlink := filepath.Join(directory, "private-key-symlink")
	require.NoError(t, goos.Symlink(target, symlink))
	_, err = loadAuditPrivateKey(symlink)
	require.ErrorContains(t, err, "not a regular file")
	hardlink := filepath.Join(directory, "private-key-hardlink")
	require.NoError(t, goos.Link(target, hardlink))
	_, err = loadAuditPrivateKey(target)
	require.ErrorContains(t, err, "hard links")
}

func TestAuditOutputRejectsEncryptionPublicKeyAliases(t *testing.T) {
	directory := t.TempDir()
	journal := filepath.Join(directory, "journal")
	require.NoError(t, goos.Mkdir(journal, 0700))
	publicKey := filepath.Join(directory, "encryption.pub")
	require.NoError(t, goos.WriteFile(publicKey, []byte("public"), 0600))
	configured := &configuration.Auditlog{
		Name:                    "default",
		Enabled:                 true,
		IdentityFile:            filepath.Join(directory, "identity"),
		EncryptionPublicKeyFile: bfcrypto.PublicKeysFile(publicKey),
		Journal:                 configuration.AuditlogJournal{Directory: journal},
	}
	conf := &configuration.Configuration{Auditlogs: configuration.Auditlogs{*configured}}
	symlink := filepath.Join(directory, "public-symlink")
	require.NoError(t, goos.Symlink(publicKey, symlink))
	require.ErrorContains(t, ensureAuditOutputSafe(symlink, conf), "must not replace encryption public key")
	hardlink := filepath.Join(directory, "public-hardlink")
	require.NoError(t, goos.Link(publicKey, hardlink))
	require.ErrorContains(t, ensureAuditOutputSafe(hardlink, conf), "must not replace encryption public key")
}

func TestAuditOutputRejectsSessionStorageAliases(t *testing.T) {
	directory := t.TempDir()
	storage := filepath.Join(directory, "sessions")
	require.NoError(t, goos.Mkdir(storage, 0700))
	sessionFile := filepath.Join(storage, "session")
	require.NoError(t, goos.WriteFile(sessionFile, []byte("recover me"), 0600))
	conf := &configuration.Configuration{Session: configuration.Session{V: &configuration.SessionFs{Storage: storage}}}

	symlinkDirectory := filepath.Join(directory, "session-alias")
	require.NoError(t, goos.Symlink(storage, symlinkDirectory))
	require.ErrorContains(t, ensureAuditOutputSafe(filepath.Join(symlinkDirectory, "export.jsonl"), conf), "must not be inside session storage")

	hardlink := filepath.Join(directory, "session-hardlink")
	require.NoError(t, goos.Link(sessionFile, hardlink))
	require.ErrorContains(t, ensureAuditOutputSafe(hardlink, conf), "must not replace session storage file")
}
