package service

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestPrepareEnsuresAuditIdentity(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "auditlog-key")
	journalDirectory := filepath.Join(directory, "auditlog")
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Auditlogs[0].Enabled = true
		conf.Auditlogs[0].IdentityFile = identityFile
		conf.Auditlogs[0].Journal.Directory = journalDirectory
	})

	identity := server.service.auditIdentities[configuration.DefaultAuditlogName]
	require.NotNil(t, identity)
	require.NotNil(t, server.service.auditRecorders[configuration.DefaultAuditlogName])
	require.Same(t, server.service.auditRecorders[configuration.DefaultAuditlogName], server.service.flowAuditRecorders[server.service.Configuration.Flows[0].Name])
	require.FileExists(t, identityFile)
	require.DirExists(t, journalDirectory)
	privateKey, err := crypto.EnsureKeyFile(identityFile, nil, nil)
	require.NoError(t, err)
	require.Equal(t, identity.Fingerprint(), gossh.FingerprintSHA256(privateKey.PublicKey().ToSsh()))
	require.Equal(t, identity.PublicKey().Marshal(), privateKey.PublicKey().Marshal())
}

func TestPrepareResolvesNamedFlowAuditlog(t *testing.T) {
	directory := t.TempDir()
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Auditlogs = append(conf.Auditlogs, configuration.Auditlog{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(directory, "security-key"),
			Journal: configuration.AuditlogJournal{
				Directory: filepath.Join(directory, "security-journal"),
			},
		})
		conf.Flows[0].Auditlog = "security"
	})

	require.Len(t, server.service.auditIdentities, 2)
	require.Len(t, server.service.auditRecorders, 2)
	require.Nil(t, server.service.auditIdentities[configuration.DefaultAuditlogName])
	require.NotNil(t, server.service.auditIdentities["security"])
	require.Same(t, server.service.auditRecorders["security"], server.service.flowAuditRecorders[server.service.Configuration.Flows[0].Name])
	require.FileExists(t, filepath.Join(directory, "security-key"))
	require.DirExists(t, filepath.Join(directory, "security-journal"))
}

func TestValidateDistinctAuditIdentity(t *testing.T) {
	key, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).GenerateKey(nil)
	require.NoError(t, err)
	identity, err := audit.NewIdentity(key)
	require.NoError(t, err)

	existing := map[configuration.AuditlogName]*audit.Identity{"first": identity}
	require.ErrorContains(t, validateDistinctAuditIdentity(existing, "second", identity), "same signing identity")
	require.NoError(t, validateDistinctAuditIdentity(existing, "disabled", nil))
}

func TestAuditEncryptionRejectsStaticSshEnvironmentIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment-key")
	key, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)
	flows := configuration.Flows{{
		Name: "ssh",
		Environment: configuration.Environment{V: &configuration.EnvironmentSsh{
			IdentityFiles: template.MustNewStrings(path),
		}},
	}}
	serverKeys, err := loadStaticPrivateKeysForAuditEncryption(flows, nil)
	require.NoError(t, err)
	publicKey := crypto.PublicKeys(string(crypto.MarshalPublicKey(key.PublicKey())))
	require.ErrorContains(t, audit.ValidateEncryptionRecipientDedicatedFrom(publicKey, serverKeys), "reuses a private key")
}
