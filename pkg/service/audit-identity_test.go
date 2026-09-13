package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestValidateRuntimePathsRejectsSessionStorageAuditOverlap(t *testing.T) {
	root := t.TempDir()
	for _, test := range []struct {
		name         string
		storage      string
		identityFile string
		journal      string
		errorPart    string
	}{
		{"journal equal", filepath.Join(root, "sessions"), filepath.Join(root, "identity"), filepath.Join(root, "sessions"), "journal"},
		{"journal below storage", filepath.Join(root, "sessions"), filepath.Join(root, "identity"), filepath.Join(root, "sessions", "audit"), "journal"},
		{"storage below journal", filepath.Join(root, "audit", "sessions"), filepath.Join(root, "identity"), filepath.Join(root, "audit"), "journal"},
		{"identity equal", filepath.Join(root, "sessions"), filepath.Join(root, "sessions"), filepath.Join(root, "audit"), "identity file"},
		{"identity below storage", filepath.Join(root, "sessions"), filepath.Join(root, "sessions", "identity"), filepath.Join(root, "audit"), "identity file"},
		{"storage below identity", filepath.Join(root, "identity", "sessions"), filepath.Join(root, "identity"), filepath.Join(root, "audit"), "identity file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := configuration.Configuration{
				Auditlogs: configuration.Auditlogs{{
					Name:         "security",
					Enabled:      true,
					IdentityFile: test.identityFile,
					Journal:      configuration.AuditlogJournal{Directory: test.journal},
				}},
				Session: configuration.Session{V: &configuration.SessionFs{Storage: test.storage}},
			}

			err := validateRuntimePaths(&conf)
			require.ErrorContains(t, err, test.errorPart)
		})
	}
}

func TestValidateRuntimePathsRejectsSessionStorageAuditInputFileOverlap(t *testing.T) {
	root := t.TempDir()
	storage := filepath.Join(root, "sessions")
	for _, test := range []struct {
		name      string
		configure func(*configuration.Auditlog)
		errorPart string
	}{
		{
			"encryption public key file",
			func(auditlog *configuration.Auditlog) {
				auditlog.EncryptionPublicKeyFile = crypto.PublicKeysFile(filepath.Join(storage, "encryption.pub"))
			},
			"encryption public key file",
		},
		{
			"SFTP known hosts file",
			func(auditlog *configuration.Auditlog) {
				auditlog.Targets = configuration.AuditlogTargets{{
					Name: "archive",
					V: &configuration.AuditlogTargetSftp{
						KnownHostsFile: crypto.KnownHostsFile(filepath.Join(storage, "known_hosts")),
					},
				}}
			},
			"SFTP target \"archive\" known hosts file",
		},
		{
			"every SFTP identity file",
			func(auditlog *configuration.Auditlog) {
				auditlog.Targets = configuration.AuditlogTargets{{
					Name: "archive",
					V: &configuration.AuditlogTargetSftp{
						IdentityFiles: []string{filepath.Join(root, "outside-key"), filepath.Join(storage, "identity")},
					},
				}}
			},
			"identity file [1]",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			auditlog := configuration.Auditlog{
				Name:         "security",
				Enabled:      true,
				IdentityFile: filepath.Join(root, "audit-identity"),
				Journal:      configuration.AuditlogJournal{Directory: filepath.Join(root, "journal")},
			}
			test.configure(&auditlog)
			conf := configuration.Configuration{
				Auditlogs: configuration.Auditlogs{auditlog},
				Session:   configuration.Session{V: &configuration.SessionFs{Storage: storage}},
			}

			require.ErrorContains(t, validateRuntimePaths(&conf), test.errorPart)
		})
	}
}

func TestValidateRuntimePathsIgnoresDisabledAuditlogWithoutSideEffects(t *testing.T) {
	storage := filepath.Join(t.TempDir(), "sessions")
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:                    configuration.DefaultAuditlogName,
			Enabled:                 false,
			IdentityFile:            filepath.Join(storage, "identity"),
			EncryptionPublicKeyFile: crypto.PublicKeysFile(filepath.Join(storage, "encryption.pub")),
			Journal:                 configuration.AuditlogJournal{Directory: storage},
			Targets: configuration.AuditlogTargets{{
				Name: "archive",
				V: &configuration.AuditlogTargetSftp{
					KnownHostsFile: crypto.KnownHostsFile(filepath.Join(storage, "known_hosts")),
					IdentityFiles:  []string{filepath.Join(storage, "archive-key")},
				},
			}},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: storage}},
	}

	require.NoError(t, validateRuntimePaths(&conf))
	require.NoFileExists(t, conf.Auditlogs[0].IdentityFile)
	require.NoFileExists(t, string(conf.Auditlogs[0].EncryptionPublicKeyFile))
	require.NoDirExists(t, storage)
}

func TestValidateRuntimePathsRewritesSymlinkAliases(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	sftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(alias, "known-hosts")),
		IdentityFiles:  []string{filepath.Join(alias, "sftp-key")},
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:                    "security",
			Enabled:                 true,
			IdentityFile:            filepath.Join(alias, "audit-key"),
			EncryptionPublicKeyFile: crypto.PublicKeysFile(filepath.Join(alias, "encryption.pub")),
			Journal:                 configuration.AuditlogJournal{Directory: filepath.Join(alias, "journal")},
			Targets:                 configuration.AuditlogTargets{{Name: "archive", V: sftp}},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(alias, "sessions")}},
	}

	require.NoError(t, validateRuntimePaths(&conf))
	require.Equal(t, filepath.Join(real, "audit-key"), conf.Auditlogs[0].IdentityFile)
	require.Equal(t, filepath.Join(real, "journal"), conf.Auditlogs[0].Journal.Directory)
	require.Equal(t, crypto.PublicKeysFile(filepath.Join(real, "encryption.pub")), conf.Auditlogs[0].EncryptionPublicKeyFile)
	require.Equal(t, filepath.Join(real, "sessions"), conf.Session.V.(*configuration.SessionFs).Storage)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(real, "known-hosts")), sftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(real, "sftp-key")}, sftp.IdentityFiles)
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

func TestPrepareAuditEncryptionValidatesSftpIdentityKeys(t *testing.T) {
	for _, test := range []struct {
		name          string
		aliasIdentity bool
		distinctKey   bool
		expectError   bool
	}{
		{"same key", false, false, true},
		{"hard-link alias", true, false, true},
		{"different key", false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			additionalIdentityPath := filepath.Join(root, "additional-sftp-key")
			_, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).CreateFile(nil, additionalIdentityPath)
			require.NoError(t, err)
			identityPath := filepath.Join(root, "sftp-key")
			identityKey, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).CreateFile(nil, identityPath)
			require.NoError(t, err)
			configuredIdentityPath := identityPath
			if test.aliasIdentity {
				configuredIdentityPath = filepath.Join(root, "sftp-key-alias")
				require.NoError(t, os.Link(identityPath, configuredIdentityPath))
			}
			encryptionKey := identityKey
			if test.distinctKey {
				encryptionKey, err = (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).CreateFile(nil, filepath.Join(root, "offline-encryption-key"))
				require.NoError(t, err)
			}

			conf := auditSftpDedicatednessTestConfiguration(t, root, []string{additionalIdentityPath, configuredIdentityPath},
				crypto.PublicKeys(strings.TrimSpace(string(crypto.MarshalPublicKey(encryptionKey.PublicKey())))))
			svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			if test.expectError {
				require.ErrorContains(t, err, "audit encryption recipient reuses a private key")
				require.Nil(t, svc)
				require.NoDirExists(t, filepath.Join(root, "journal"))
				return
			}
			require.NoError(t, err)
			require.NotNil(t, svc)
			require.NoError(t, svc.Close())
		})
	}
}

func auditSftpDedicatednessTestConfiguration(t *testing.T, root string, sftpIdentities []string, encryptionKey crypto.PublicKeys) configuration.Configuration {
	t.Helper()
	var conf configuration.Configuration
	err := conf.LoadFromYaml(strings.NewReader(fmt.Sprintf(`
ssh:
  addresses: ["127.0.0.1:0"]
  keys:
    hostKeys: ["%s"]
  banner: ""
session:
  type: fs
  storage: "%s"
flows:
  - name: test
    authorization:
      type: none
    environment:
      type: dummy
`, filepath.ToSlash(filepath.Join(root, "host-key")), filepath.ToSlash(filepath.Join(root, "sessions")))), "audit-sftp-dedicatedness-test.yaml")
	require.NoError(t, err)
	require.Len(t, conf.Auditlogs, 1)
	auditlog := &conf.Auditlogs[0]
	auditlog.Enabled = true
	auditlog.IdentityFile = filepath.Join(root, "audit-key")
	auditlog.EncryptionPublicKey = encryptionKey
	auditlog.Journal.Directory = filepath.Join(root, "journal")
	sftp := &configuration.AuditlogTargetSftp{}
	require.NoError(t, sftp.SetDefaults())
	sftp.Address = "127.0.0.1:1"
	sftp.User = template.MustNewString("archive")
	sftp.Directory = "/archive"
	sftp.AcceptAllHostKeys = true
	sftp.IdentityFiles = sftpIdentities
	auditlog.Targets = configuration.AuditlogTargets{{Name: "archive", V: sftp}}
	return conf
}

func TestPrepareActivatesRemoteAuditDelivery(t *testing.T) {
	directory := t.TempDir()
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		auditlog := &conf.Auditlogs[0]
		auditlog.Enabled = true
		auditlog.IdentityFile = filepath.Join(directory, "auditlog-key")
		auditlog.Journal.Directory = filepath.Join(directory, "auditlog")
		auditlog.Targets = configuration.AuditlogTargets{{
			Name: "archive",
			V: &configuration.AuditlogTargetS3{
				Bucket:              "audit-archive",
				Region:              template.MustNewString("eu-central-1"),
				Endpoint:            "https://127.0.0.1:1",
				PathStyle:           true,
				DestinationIdentity: "service-test-tenant",
				AccessKeyId:         template.MustNewString("access"),
				SecretAccessKey:     template.MustNewString("secret"),
				SessionToken:        template.MustNewString(""),
			},
		}}
	})

	delivery := server.service.auditDeliveries[configuration.DefaultAuditlogName]
	require.NotNil(t, delivery)
	identity := server.service.auditIdentities[configuration.DefaultAuditlogName]
	targetStateRoot := filepath.Join(directory, "auditlog", ".delivery", identity.ProducerId().String())
	entries, err := os.ReadDir(targetStateRoot)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.True(t, entries[0].IsDir())
}
