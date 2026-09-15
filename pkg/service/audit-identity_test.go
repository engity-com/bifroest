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
	recordingSftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(alias, "recording-known-hosts")),
		IdentityFiles:  []string{filepath.Join(alias, "recording-sftp-key")},
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:                    "security",
			Enabled:                 true,
			IdentityFile:            filepath.Join(alias, "audit-key"),
			EncryptionPublicKeyFile: crypto.PublicKeysFile(filepath.Join(alias, "encryption.pub")),
			Journal:                 configuration.AuditlogJournal{Directory: filepath.Join(alias, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   true,
				Directory: filepath.Join(alias, "recordings"),
				Targets:   recordingSftpTargets(recordingSftp),
			},
			Targets: configuration.AuditlogTargets{{Name: "archive", V: sftp}},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(alias, "sessions")}},
	}

	require.NoError(t, validateRuntimePaths(&conf))
	canonicalReal, err := filepath.EvalSymlinks(real)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(canonicalReal, "audit-key"), conf.Auditlogs[0].IdentityFile)
	require.Equal(t, filepath.Join(canonicalReal, "journal"), conf.Auditlogs[0].Journal.Directory)
	require.Equal(t, filepath.Join(canonicalReal, "recordings"), conf.Auditlogs[0].Recording.Directory)
	require.Equal(t, crypto.PublicKeysFile(filepath.Join(canonicalReal, "encryption.pub")), conf.Auditlogs[0].EncryptionPublicKeyFile)
	require.Equal(t, filepath.Join(canonicalReal, "sessions"), conf.Session.V.(*configuration.SessionFs).Storage)
	resolvedSftp := conf.Auditlogs[0].Targets[0].V.(*configuration.AuditlogTargetSftp)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(canonicalReal, "known-hosts")), resolvedSftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(canonicalReal, "sftp-key")}, resolvedSftp.IdentityFiles)
	resolvedRecordingSftp := conf.Auditlogs[0].Recording.Targets.Configured()[0].V.(*configuration.AuditlogTargetSftp)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(canonicalReal, "recording-known-hosts")), resolvedRecordingSftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(canonicalReal, "recording-sftp-key")}, resolvedRecordingSftp.IdentityFiles)
}

func TestValidateRuntimePathsRejectsRecordingSymlinkOverlap(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(real, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: filepath.Join(real, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   true,
				Directory: filepath.Join(alias, "journal", "recordings"),
			},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(real, "sessions")}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "recording directory overlaps auditlog \"security\" journal")
}

func TestValidateRuntimePathsRejectsRecordingSessionStorageSymlinkOverlap(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(real, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: filepath.Join(real, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   true,
				Directory: filepath.Join(alias, "storage", "recordings"),
			},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(real, "storage")}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "recording directory overlaps session storage")
}

func TestValidateRuntimePathsRejectsRecordingTargetInputSymlinkOverlap(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	sftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(real, "recordings", "known_hosts")),
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(real, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: filepath.Join(real, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   true,
				Directory: filepath.Join(alias, "recordings"),
			},
			Targets: configuration.AuditlogTargets{{Name: "archive", V: sftp}},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(real, "sessions")}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "recording directory overlaps auditlog \"security\" SFTP target \"archive\" known hosts file")
}

func TestValidateRuntimePathsRejectsCustomRecordingTargetCrossRootSymlinkOverlap(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	recordingSftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(real, "first-recordings", "known_hosts")),
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{
			{
				Name:         "first",
				Enabled:      true,
				IdentityFile: filepath.Join(real, "first-identity"),
				Journal:      configuration.AuditlogJournal{Directory: filepath.Join(real, "first-journal")},
				Recording: configuration.AuditlogRecording{
					Enabled:   true,
					Directory: filepath.Join(alias, "first-recordings"),
				},
			},
			{
				Name:         "second",
				Enabled:      true,
				IdentityFile: filepath.Join(real, "second-identity"),
				Journal:      configuration.AuditlogJournal{Directory: filepath.Join(real, "second-journal")},
				Recording: configuration.AuditlogRecording{
					Enabled:   true,
					Directory: filepath.Join(alias, "second-recordings"),
					Targets:   recordingSftpTargets(recordingSftp),
				},
			},
		},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "recording directory overlaps auditlog \"second\" Recording SFTP target \"recording-archive\" known hosts file")
}

func TestValidateRuntimePathsRejectsCustomRecordingTargetSessionStorageOverlap(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	recordingSftp := &configuration.AuditlogTargetSftp{
		IdentityFiles: []string{filepath.Join(alias, "sessions", "recording-key")},
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(real, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: filepath.Join(real, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   true,
				Directory: filepath.Join(real, "recordings"),
				Targets:   recordingSftpTargets(recordingSftp),
			},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(real, "sessions")}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "session storage overlaps auditlog \"security\" Recording SFTP target \"recording-archive\" identity file [0]")
}

func TestValidateRuntimePathsRejectsCrossAuditlogRecordingCredentialSymlinkOverlaps(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}

	for _, test := range []struct {
		name      string
		configure func(*configuration.Auditlog)
		errorPart string
	}{
		{
			"encryption public key file",
			func(auditlog *configuration.Auditlog) {
				auditlog.EncryptionPublicKeyFile = crypto.PublicKeysFile(filepath.Join(real, "recordings", "recipient.pub"))
			},
			"auditlog \"second\" encryption public key file",
		},
		{
			"SFTP known hosts file",
			func(auditlog *configuration.Auditlog) {
				auditlog.Targets = configuration.AuditlogTargets{{
					Name: "archive",
					V: &configuration.AuditlogTargetSftp{
						KnownHostsFile: crypto.KnownHostsFile(filepath.Join(real, "recordings", "known_hosts")),
					},
				}}
			},
			"auditlog \"second\" SFTP target \"archive\" known hosts file",
		},
		{
			"SFTP identity file",
			func(auditlog *configuration.Auditlog) {
				auditlog.Targets = configuration.AuditlogTargets{{
					Name: "archive",
					V: &configuration.AuditlogTargetSftp{
						IdentityFiles: []string{filepath.Join(real, "recordings", "identity")},
					},
				}}
			},
			"auditlog \"second\" SFTP target \"archive\" identity file [0]",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := configuration.Auditlog{
				Name:         "first",
				Enabled:      true,
				IdentityFile: filepath.Join(real, "first-identity"),
				Journal:      configuration.AuditlogJournal{Directory: filepath.Join(real, "first-journal")},
				Recording: configuration.AuditlogRecording{
					Enabled:   true,
					Directory: filepath.Join(alias, "recordings"),
				},
			}
			second := configuration.Auditlog{
				Name:         "second",
				Enabled:      true,
				IdentityFile: filepath.Join(real, "second-identity"),
				Journal:      configuration.AuditlogJournal{Directory: filepath.Join(real, "second-journal")},
			}
			test.configure(&second)
			conf := configuration.Configuration{Auditlogs: configuration.Auditlogs{first, second}}

			require.ErrorContains(t, validateRuntimePaths(&conf), test.errorPart)
		})
	}
}

func TestValidateRuntimePathsIsAtomicAfterLateRecordingOverlap(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	sftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(alias, "known_hosts")),
		IdentityFiles:  []string{filepath.Join(alias, "recordings", "identity")},
	}
	recordingSftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(alias, "recording-known-hosts")),
		IdentityFiles:  []string{filepath.Join(alias, "recording-identity")},
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{
			{
				Name:                    "first",
				Enabled:                 true,
				IdentityFile:            filepath.Join(alias, "first-identity"),
				EncryptionPublicKeyFile: crypto.PublicKeysFile(filepath.Join(alias, "recipient.pub")),
				Journal:                 configuration.AuditlogJournal{Directory: filepath.Join(alias, "first-journal")},
				Recording: configuration.AuditlogRecording{
					Enabled:   true,
					Directory: filepath.Join(alias, "recordings"),
					Targets:   recordingSftpTargets(recordingSftp),
				},
			},
			{
				Name:         "second",
				Enabled:      true,
				IdentityFile: filepath.Join(alias, "second-identity"),
				Journal:      configuration.AuditlogJournal{Directory: filepath.Join(alias, "second-journal")},
				Targets:      configuration.AuditlogTargets{{Name: "archive", V: sftp}},
			},
		},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(alias, "sessions")}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "recording directory overlaps auditlog \"second\" SFTP target \"archive\" identity file")
	require.Equal(t, filepath.Join(alias, "first-identity"), conf.Auditlogs[0].IdentityFile)
	require.Equal(t, filepath.Join(alias, "first-journal"), conf.Auditlogs[0].Journal.Directory)
	require.Equal(t, filepath.Join(alias, "recordings"), conf.Auditlogs[0].Recording.Directory)
	require.Equal(t, crypto.PublicKeysFile(filepath.Join(alias, "recipient.pub")), conf.Auditlogs[0].EncryptionPublicKeyFile)
	require.Equal(t, filepath.Join(alias, "sessions"), conf.Session.V.(*configuration.SessionFs).Storage)
	require.Same(t, sftp, conf.Auditlogs[1].Targets[0].V)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(alias, "known_hosts")), sftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(alias, "recordings", "identity")}, sftp.IdentityFiles)
	require.Same(t, recordingSftp, conf.Auditlogs[0].Recording.Targets.Configured()[0].V)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(alias, "recording-known-hosts")), recordingSftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(alias, "recording-identity")}, recordingSftp.IdentityFiles)
}

func TestValidateRuntimePathsIsAtomicAfterRecordingCanonicalizationFailure(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	sftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(alias, "known_hosts")),
		IdentityFiles:  []string{filepath.Join(alias, "sftp-identity")},
	}
	recordingDirectory := filepath.Join(alias, "recordings") + "\x00"
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(alias, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: filepath.Join(alias, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   true,
				Directory: recordingDirectory,
			},
			Targets: configuration.AuditlogTargets{{Name: "archive", V: sftp}},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(alias, "sessions")}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "cannot resolve recording directory")
	require.Equal(t, filepath.Join(alias, "identity"), conf.Auditlogs[0].IdentityFile)
	require.Equal(t, filepath.Join(alias, "journal"), conf.Auditlogs[0].Journal.Directory)
	require.Equal(t, recordingDirectory, conf.Auditlogs[0].Recording.Directory)
	require.Equal(t, filepath.Join(alias, "sessions"), conf.Session.V.(*configuration.SessionFs).Storage)
	require.Same(t, sftp, conf.Auditlogs[0].Targets[0].V)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(alias, "known_hosts")), sftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(alias, "sftp-identity")}, sftp.IdentityFiles)
}

func TestValidateRuntimePathsIsAtomicAfterCustomRecordingTargetFailure(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	parentSftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(alias, "parent-known-hosts")),
		IdentityFiles:  []string{filepath.Join(alias, "parent-identity")},
	}
	recordingSftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(alias, "recording-known-hosts")),
		IdentityFiles:  []string{filepath.Join(alias, "recording-identity") + "\x00"},
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:                    "security",
			Enabled:                 true,
			IdentityFile:            filepath.Join(alias, "identity"),
			EncryptionPublicKeyFile: crypto.PublicKeysFile(filepath.Join(alias, "recipient.pub")),
			Journal:                 configuration.AuditlogJournal{Directory: filepath.Join(alias, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   true,
				Directory: filepath.Join(alias, "recordings"),
				Targets:   recordingSftpTargets(recordingSftp),
			},
			Targets: configuration.AuditlogTargets{{Name: "archive", V: parentSftp}},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(alias, "sessions")}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "cannot resolve auditlog \"security\" Recording SFTP target \"recording-archive\" identity file [0]")
	require.Equal(t, filepath.Join(alias, "identity"), conf.Auditlogs[0].IdentityFile)
	require.Equal(t, filepath.Join(alias, "journal"), conf.Auditlogs[0].Journal.Directory)
	require.Equal(t, filepath.Join(alias, "recordings"), conf.Auditlogs[0].Recording.Directory)
	require.Equal(t, crypto.PublicKeysFile(filepath.Join(alias, "recipient.pub")), conf.Auditlogs[0].EncryptionPublicKeyFile)
	require.Equal(t, filepath.Join(alias, "sessions"), conf.Session.V.(*configuration.SessionFs).Storage)
	require.Same(t, parentSftp, conf.Auditlogs[0].Targets[0].V)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(alias, "parent-known-hosts")), parentSftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(alias, "parent-identity")}, parentSftp.IdentityFiles)
	require.Same(t, recordingSftp, conf.Auditlogs[0].Recording.Targets.Configured()[0].V)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(alias, "recording-known-hosts")), recordingSftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(alias, "recording-identity") + "\x00"}, recordingSftp.IdentityFiles)
}

func TestValidateRuntimePathsDoesNotCanonicalizeDisabledRecording(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	recordingDirectory := filepath.Join(alias, "recordings")
	recordingSftp := &configuration.AuditlogTargetSftp{
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(alias, "recording-known-hosts") + "\x00"),
		IdentityFiles:  []string{filepath.Join(alias, "recording-identity") + "\x00"},
	}
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(alias, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: filepath.Join(alias, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   false,
				Directory: recordingDirectory,
				Targets:   recordingSftpTargets(recordingSftp),
			},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(alias, "sessions")}},
	}

	require.NoError(t, validateRuntimePaths(&conf))
	require.Equal(t, recordingDirectory, conf.Auditlogs[0].Recording.Directory)
	require.Same(t, recordingSftp, conf.Auditlogs[0].Recording.Targets.Configured()[0].V)
	require.Equal(t, crypto.KnownHostsFile(filepath.Join(alias, "recording-known-hosts")+"\x00"), recordingSftp.KnownHostsFile)
	require.Equal(t, []string{filepath.Join(alias, "recording-identity") + "\x00"}, recordingSftp.IdentityFiles)
	require.NoDirExists(t, recordingDirectory)
}

func recordingSftpTargets(sftp *configuration.AuditlogTargetSftp) configuration.AuditlogRecordingTargets {
	return configuration.AuditlogRecordingTargets{
		Mode:    configuration.AuditlogRecordingTargetsModeCustom,
		Targets: configuration.AuditlogTargets{{Name: "recording-archive", V: sftp}},
	}
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
		customTarget  bool
		errorContains string
	}{
		{"same key", false, false, false, "audit encryption recipient reuses a private key"},
		{"same key in custom Recording target", false, false, true, "audit encryption recipient reuses a private key"},
		{"hard-link alias", true, false, false, "has 2 hard links instead of one"},
		{"different key", false, true, false, ""},
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
			if test.customTarget {
				auditlog := &conf.Auditlogs[0]
				require.NoError(t, auditlog.Recording.SetDefaults())
				auditlog.Recording.Enabled = true
				auditlog.Recording.Directory = filepath.Join(root, "recordings")
				auditlog.Recording.Targets = configuration.AuditlogRecordingTargets{
					Mode:    configuration.AuditlogRecordingTargetsModeCustom,
					Targets: auditlog.Targets,
				}
				auditlog.Targets = nil
			}
			svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			if test.errorContains != "" {
				require.ErrorContains(t, err, test.errorContains)
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
