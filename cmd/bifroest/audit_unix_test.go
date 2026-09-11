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

func TestAuditOutputRejectsSymlinkIntoJournal(t *testing.T) {
	directory := t.TempDir()
	journal := filepath.Join(directory, "journal")
	require.NoError(t, goos.Mkdir(journal, 0700))
	alias := filepath.Join(directory, "alias")
	require.NoError(t, goos.Symlink(journal, alias))
	configured := &configuration.Auditlog{
		Name:         "default",
		IdentityFile: filepath.Join(directory, "identity"),
		Journal:      configuration.AuditlogJournal{Directory: journal},
	}

	err := ensureAuditOutputSafe(filepath.Join(alias, "export.jsonl"), []*configuration.Auditlog{configured})
	require.ErrorContains(t, err, "must not be inside")
}

func TestLoadAuditPrivateKeyRejectsInsecureMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-key")
	require.NoError(t, goos.WriteFile(path, []byte("not relevant"), 0644))
	_, err := loadAuditPrivateKey(path)
	require.ErrorContains(t, err, "accessible by group or others")
}

func TestAuditOutputRejectsEncryptionPublicKeyAliases(t *testing.T) {
	directory := t.TempDir()
	journal := filepath.Join(directory, "journal")
	require.NoError(t, goos.Mkdir(journal, 0700))
	publicKey := filepath.Join(directory, "encryption.pub")
	require.NoError(t, goos.WriteFile(publicKey, []byte("public"), 0600))
	configured := &configuration.Auditlog{
		Name:                    "default",
		IdentityFile:            filepath.Join(directory, "identity"),
		EncryptionPublicKeyFile: bfcrypto.PublicKeysFile(publicKey),
		Journal:                 configuration.AuditlogJournal{Directory: journal},
	}
	symlink := filepath.Join(directory, "public-symlink")
	require.NoError(t, goos.Symlink(publicKey, symlink))
	require.ErrorContains(t, ensureAuditOutputSafe(symlink, []*configuration.Auditlog{configured}), "must not replace encryption public key")
	hardlink := filepath.Join(directory, "public-hardlink")
	require.NoError(t, goos.Link(publicKey, hardlink))
	require.ErrorContains(t, ensureAuditOutputSafe(hardlink, []*configuration.Auditlog{configured}), "must not replace encryption public key")
}
