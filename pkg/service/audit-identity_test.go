package service

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestPrepareEnsuresAuditIdentity(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "auditlog-key")
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Auditlog.Enabled = true
		conf.Auditlog.IdentityFile = identityFile
		conf.Auditlog.Journal.Directory = filepath.Join(directory, "auditlog")
	})

	require.NotNil(t, server.service.auditIdentity)
	require.FileExists(t, identityFile)
	privateKey, err := crypto.EnsureKeyFile(identityFile, nil, nil)
	require.NoError(t, err)
	require.Equal(t, server.service.auditIdentity.Fingerprint(), gossh.FingerprintSHA256(privateKey.PublicKey().ToSsh()))
	require.Equal(t, server.service.auditIdentity.PublicKey().Marshal(), privateKey.PublicKey().Marshal())
}
