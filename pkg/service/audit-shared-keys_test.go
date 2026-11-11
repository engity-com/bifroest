package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfconnection "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestPrepareSharedAuditKeys(t *testing.T) {
	for _, signing := range []string{"same file", "copied key", "generated shared key", "distinct keys"} {
		for _, encryption := range []string{"clear", "same recipient", "same recipient file"} {
			t.Run(signing+"/"+encryption, func(t *testing.T) {
				root := t.TempDir()
				conf := sessionRecordingTestConfiguration(t, root)
				enableSessionRecording(&conf.Auditlogs[0])
				second := conf.Auditlogs[0]
				second.Name = "second"
				second.Directory = filepath.Join(root, "second-journal")
				second.Recording.Directory = filepath.Join(root, "second-recordings")
				if signing != "generated shared key" {
					_, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).CreateFile(nil, conf.Auditlogs[0].IdentityFile)
					require.NoError(t, err)
				}
				if signing == "copied key" || signing == "distinct keys" {
					second.IdentityFile = filepath.Join(root, "second-key")
					if signing == "copied key" {
						contents, err := os.ReadFile(conf.Auditlogs[0].IdentityFile)
						require.NoError(t, err)
						writeCopiedAuditTestKey(t, second.IdentityFile, contents)
					}
				}
				var privateKeys []crypto.PrivateKey
				if encryption != "clear" {
					key, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).GenerateKey(nil)
					require.NoError(t, err)
					privateKeys = []crypto.PrivateKey{key}
					public := strings.TrimSpace(string(crypto.MarshalPublicKey(key.PublicKey())))
					if encryption == "same recipient file" {
						path := filepath.Join(root, "recipient.pub")
						require.NoError(t, os.WriteFile(path, []byte(public), 0600))
						conf.Auditlogs[0].EncryptionPublicKeyFile = crypto.PublicKeysFile(path)
						second.EncryptionPublicKeyFile = crypto.PublicKeysFile(path)
					} else {
						conf.Auditlogs[0].EncryptionPublicKey = crypto.PublicKeys(public)
						second.EncryptionPublicKey = crypto.PublicKeys(public)
					}
				}
				conf.Auditlogs = append(conf.Auditlogs, second)
				svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
				require.NoError(t, err)
				t.Cleanup(func() {
					if svc != nil {
						require.NoError(t, svc.Close())
					}
				})
				firstIdentity := svc.auditIdentities[conf.Auditlogs[0].Name]
				secondIdentity := svc.auditIdentities[second.Name]
				require.NotNil(t, firstIdentity)
				require.NotNil(t, secondIdentity)
				if signing == "distinct keys" {
					require.NotEqual(t, firstIdentity.ProducerId(), secondIdentity.ProducerId())
				} else {
					require.Equal(t, firstIdentity.ProducerId(), secondIdentity.ProducerId())
				}
				require.NotSame(t, svc.auditRecorders[conf.Auditlogs[0].Name], svc.auditRecorders[second.Name])
				require.NotSame(t, svc.recordingRepositories[conf.Auditlogs[0].Name], svc.recordingRepositories[second.Name])
				var sources []audit.JournalSource
				for _, configured := range conf.Auditlogs {
					identity := svc.auditIdentities[configured.Name]
					require.NoError(t, svc.auditRecorders[configured.Name].Record(t.Context(), audit.Event{Name: "test.shared-key", Reason: string(configured.Name)}))
					verifySharedKeyRecording(t, svc.recordingRepositories[configured.Name], configured, identity, privateKeys)
					publicKey, err := audit.ResolveEncryptionPublicKey(configured.EncryptionPublicKey, configured.EncryptionPublicKeyFile)
					require.NoError(t, err)
					recipient, err := audit.EncryptionRecipientFingerprint(publicKey)
					require.NoError(t, err)
					sources = append(sources, audit.JournalSource{Name: string(configured.Name), Directory: configured.Directory, ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: recipient, WithSensitive: true, DecryptionIdentities: privateKeys})
				}
				require.NoError(t, svc.Close())
				svc = nil
				verified, err := audit.VerifyJournals(t.Context(), sources)
				require.NoError(t, err)
				require.Len(t, verified.Journals, 2)
				found := map[string]int{}
				for _, entry := range verified.Records() {
					if entry.Event.Name == "test.shared-key" {
						require.Equal(t, entry.Auditlog, entry.Event.Reason)
						found[entry.Auditlog]++
					}
				}
				require.Equal(t, map[string]int{string(conf.Auditlogs[0].Name): 1, string(second.Name): 1}, found)
				restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
				require.NoError(t, err)
				require.Equal(t, firstIdentity.ProducerId(), restarted.auditIdentities[conf.Auditlogs[0].Name].ProducerId())
				require.Equal(t, secondIdentity.ProducerId(), restarted.auditIdentities[second.Name].ProducerId())
				require.NoError(t, restarted.Close())
			})
		}
	}
}

func TestPrepareSharedAuditIdentityThroughDirectoryAlias(t *testing.T) {
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	_, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).CreateFile(nil, conf.Auditlogs[0].IdentityFile)
	require.NoError(t, err)
	alias := filepath.Join(root, "key-directory-alias")
	if err := os.Symlink(filepath.Dir(conf.Auditlogs[0].IdentityFile), alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	second := conf.Auditlogs[0]
	second.Name = "second"
	second.IdentityFile = filepath.Join(alias, filepath.Base(second.IdentityFile))
	second.Directory = filepath.Join(root, "second-journal")
	conf.Auditlogs = append(conf.Auditlogs, second)
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	require.Equal(t, svc.Configuration.Auditlogs[0].IdentityFile, svc.Configuration.Auditlogs[1].IdentityFile)
	require.Equal(t, svc.auditIdentities[conf.Auditlogs[0].Name].ProducerId(), svc.auditIdentities[second.Name].ProducerId())
}

func TestPrepareMissingSharedAuditIdentityPreservesOtherHistory(t *testing.T) {
	for _, kind := range []string{"journal", "disabled recording"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			conf := sessionRecordingTestConfiguration(t, root)
			second := conf.Auditlogs[0]
			second.Name = "second"
			second.Directory = filepath.Join(root, "second-journal")
			second.Recording.Directory = filepath.Join(root, "second-recordings")
			conf.Auditlogs = append(conf.Auditlogs, second)
			directory := second.Directory
			if kind == "disabled recording" {
				directory = second.Recording.Directory
			}
			require.NoError(t, os.MkdirAll(directory, 0700))
			marker := filepath.Join(directory, "existing-state")
			require.NoError(t, os.WriteFile(marker, []byte("original evidence"), 0600))
			svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
			require.Nil(t, svc)
			require.ErrorContains(t, err, "is missing while")
			require.NoFileExists(t, conf.Auditlogs[0].IdentityFile)
			require.NoDirExists(t, conf.Auditlogs[0].Directory)
			contents, err := os.ReadFile(marker)
			require.NoError(t, err)
			require.Equal(t, "original evidence", string(contents))
		})
	}
}

func verifySharedKeyRecording(t *testing.T, repository *sessionRecordingRepository, configured configuration.Auditlog, identity *audit.Identity, privateKeys []crypto.PrivateKey) {
	t.Helper()
	started := time.Now().UTC()
	id, err := recording.NewId()
	require.NoError(t, err)
	metadata := recording.CastMetadata{RecordingId: id, ConnectionId: bfconnection.MustNewId(), SessionId: session.MustNewId(), OperationId: uuid.New(), Flow: "shared-key", Task: audit.SessionTaskExec, ProducerId: identity.ProducerId(), StartedAt: started}
	filename, err := repository.artifactName(id)
	require.NoError(t, err)
	require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), filename, started, sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)))
	active, err := repository.createActive(t.Context(), recording.CastHeader{Version: 3, Terminal: recording.CastTerminal{Columns: 80, Rows: 24, Type: "xterm"}, Timestamp: started.Unix()}, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Millisecond, recording.OutputStreamStdout, []byte(configured.Name)))
	exit := uint32(0)
	require.NoError(t, repository.receipts.StageLifecycle(t.Context(), filename, sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingCompleted, audit.EventOutcomeSuccess, "", nil, time.Second, nil, &exit)))
	_, err = active.Seal(time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: started.Add(time.Second)}, &exit)
	require.NoError(t, err)
	require.NoError(t, active.Close())
	file, err := os.Open(filepath.Join(configured.Recording.Directory, "sealed", filename))
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	info, err := file.Stat()
	require.NoError(t, err)
	var identities *crypto.AgeSshIdentities
	if len(privateKeys) > 0 {
		identities, err = crypto.NewAgeSshIdentities(privateKeys)
		require.NoError(t, err)
	}
	verified, err := recording.VerifyNativeRecordingFull(file, info.Size(), identities, recording.NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, id, recording.Id(verified.Header.RecordingId))
}
