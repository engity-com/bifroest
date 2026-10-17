package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestAuditCommandsDecryptEncryptedJournal(t *testing.T) {
	root := t.TempDir()
	key, publicPath := createAuditCliTestKeyPair(t, root, "recipient")
	wrongKey, _ := createAuditCliTestKeyPair(t, root, "wrong-recipient")
	public, err := os.ReadFile(publicPath)
	require.NoError(t, err)
	encrypted := createAuditCliTestJournalWithEncryption(t, root, "encrypted", "test.secret", bfcrypto.PublicKeys(public))
	encrypted.EncryptionPublicKey, encrypted.EncryptionPublicKeyFile = "", bfcrypto.PublicKeysFile(publicPath)
	plain := createAuditCliTestJournal(t, root, "plain", "test.plain")
	configurationPath := writeAuditCliTestConfiguration(t, root, encrypted, plain)
	app := newAuditCliTestApplication(t)
	verify := []string{"audit", "verify", "encrypted", "--configuration=" + configurationPath}
	for _, test := range []struct {
		flags []string
		scope string
	}{
		{nil, "outer"},
		{[]string{"--decryptionIdentityFile=" + key, "--require-full"}, "full"},
		{[]string{"--require-full"}, ""},
		{[]string{"--decryptionIdentityFile=" + wrongKey}, ""},
	} {
		var output bytes.Buffer
		err := runAuditCliTestCommand(t, app, &output, append(verify, test.flags...)...)
		if test.scope == "" {
			require.Error(t, err)
			require.Empty(t, output.Bytes())
		} else {
			require.NoError(t, err)
			require.Equal(t, "verified (scope: "+test.scope+")\n", output.String())
		}
	}
	for _, command := range []string{"export", "decrypt", "merge"} {
		t.Run(command, func(t *testing.T) {
			args := []string{"audit", command, "encrypted", "--configuration=" + configurationPath}
			if command == "merge" {
				args = append(args, "plain")
			}
			var redacted bytes.Buffer
			require.NoError(t, runAuditCliTestCommand(t, app, &redacted, args...))
			require.Contains(t, redacted.String(), `"name":"test.secret"`)
			require.NotContains(t, redacted.String(), "confidential-flow")
			require.NotContains(t, redacted.String(), "internal-detail")
			for _, identity := range []string{key, wrongKey, filepath.Join(root, "missing-key")} {
				var output bytes.Buffer
				require.NoError(t, runAuditCliTestCommand(t, app, &output, append(args, "--decryptionIdentityFile="+identity)...))
				require.Equal(t, redacted.Bytes(), output.Bytes(), "redacted export must not depend on a decryption key")
			}
			for _, identity := range []string{"", wrongKey, filepath.Join(root, "missing-key"), key} {
				flags := append([]string{}, args...)
				flags = append(flags, "--with-sensitive")
				if identity != "" {
					flags = append(flags, "--decryptionIdentityFile="+identity)
				}
				var output bytes.Buffer
				err := runAuditCliTestCommand(t, app, &output, flags...)
				if identity == key {
					require.NoError(t, err)
					require.Contains(t, output.String(), "confidential-flow-encrypted")
					require.Contains(t, output.String(), "internal-detail")
					if command == "merge" {
						require.Contains(t, output.String(), "confidential-flow-plain")
					}
				} else {
					require.Error(t, err)
					require.Empty(t, output.Bytes())
				}
			}
			var publicAgain bytes.Buffer
			require.NoError(t, runAuditCliTestCommand(t, app, &publicAgain, args...))
			require.Equal(t, redacted.Bytes(), publicAgain.Bytes(), "sensitive options must not leak into the next invocation")
		})
	}
}

func TestAuditOfflineCommandsVerifyTrustAndScopeWithoutSigningKey(t *testing.T) {
	root := t.TempDir()
	key, publicPath := createAuditCliTestKeyPair(t, root, "recipient")
	wrongKey, _ := createAuditCliTestKeyPair(t, root, "wrong-recipient")
	public, err := os.ReadFile(publicPath)
	require.NoError(t, err)
	configured := createAuditCliTestJournalWithEncryption(t, root, "default", "test.offline", bfcrypto.PublicKeys(public))
	producer := auditCliTestProducerId(t, configured.IdentityFile).String()
	configurationPath := writeAuditCliTestConfiguration(t, root, configured)
	require.NoError(t, os.Remove(configured.IdentityFile))
	app := newAuditCliTestApplication(t)
	for _, command := range []string{"verify", "export", "decrypt"} {
		t.Run(command, func(t *testing.T) {
			base := []string{"audit", command, "--source=" + configured.Directory}
			trusted := []string{"--expectedProducerId=" + producer, "--encryptionPublicKeyFile=" + publicPath}
			var output bytes.Buffer
			require.NoError(t, runAuditCliTestCommand(t, app, &output, append(base, trusted...)...))
			if command == "verify" {
				require.Equal(t, "verified (scope: outer)\n", output.String())
				head := filepath.Join(configured.Directory, producer, "head.cbor")
				before, err := os.ReadFile(head)
				require.NoError(t, err)
				require.NoError(t, os.Chmod(head, 0600))
				stdout, err := os.OpenFile(head, os.O_WRONLY|os.O_APPEND, 0)
				require.NoError(t, err)
				err = runAuditCliTestCommand(t, app, stdout, append(base, trusted...)...)
				require.NoError(t, stdout.Close())
				require.ErrorContains(t, err, "journal file")
				requireAuditCliTestFileUnchanged(t, head, before)
			} else {
				require.Contains(t, output.String(), `"name":"test.offline"`)
				require.NotContains(t, output.String(), "confidential-flow")
			}
			flags := []string{"--expectedProducerId=" + producer, "--decryptionIdentityFile=" + key}
			if command == "verify" {
				flags = append(flags, "--require-full")
			} else {
				flags = append(flags, "--with-sensitive")
			}
			output.Reset()
			require.NoError(t, runAuditCliTestCommand(t, app, &output, append(base, flags...)...))
			if command == "verify" {
				require.Equal(t, "verified (scope: full)\n", output.String())
			} else {
				require.Contains(t, output.String(), "confidential-flow-default")
			}
			for _, test := range []struct {
				name       string
				flags      []string
				requireKey bool
			}{
				{"missing-trust", []string{"--encryptionPublicKeyFile=" + publicPath}, false},
				{"wrong-producer", []string{"--expectedProducerId=" + strings.Repeat("1", 64), "--encryptionPublicKeyFile=" + publicPath}, false},
				{"missing-recipient", []string{"--expectedProducerId=" + producer}, false},
				{"wrong-key", []string{"--expectedProducerId=" + producer, "--decryptionIdentityFile=" + wrongKey}, true},
				{"missing-key", trusted, true},
				{"configuration-conflict", append(append([]string{}, trusted...), "--configuration="+configurationPath), false},
			} {
				t.Run(test.name, func(t *testing.T) {
					args := append(append([]string{}, base...), test.flags...)
					if test.requireKey {
						flag := "--with-sensitive"
						if command == "verify" {
							flag = "--require-full"
						}
						args = append(args, flag)
					}
					var output bytes.Buffer
					require.Error(t, runAuditCliTestCommand(t, app, &output, args...))
					require.Empty(t, output.Bytes())
				})
			}
			require.NoFileExists(t, configured.IdentityFile)
		})
	}
}

func TestAuditExportOfflineClearWithoutConfiguration(t *testing.T) {
	root := t.TempDir()
	configured := createAuditCliTestJournal(t, root, "default", "test.clear-offline")
	producer := auditCliTestProducerId(t, configured.IdentityFile).String()
	require.NoError(t, os.Remove(configured.IdentityFile))
	app := newAuditCliTestApplication(t)
	var output bytes.Buffer
	require.NoError(t, runAuditCliTestCommand(t, app, &output, "audit", "export",
		"--source="+configured.Directory, "--expectedProducerId="+producer, "--with-sensitive"))
	require.Contains(t, output.String(), "confidential-flow-default")
	require.NoFileExists(t, configured.IdentityFile)
}

func TestAuditCommandsUseExplicitProducerTrustAnchorsWithoutSigningKeys(t *testing.T) {
	root := t.TempDir()
	first := createAuditCliTestJournal(t, root, "first", "test.first")
	second := createAuditCliTestJournal(t, root, "second", "test.second")
	configurationPath := writeAuditCliTestConfiguration(t, root, first, second)
	firstID, secondID := auditCliTestProducerId(t, first.IdentityFile).String(), auditCliTestProducerId(t, second.IdentityFile).String()
	app := newAuditCliTestApplication(t)
	var producer bytes.Buffer
	require.NoError(t, runAuditCliTestCommand(t, app, &producer, "audit", "producer-id", "first", "--configuration="+configurationPath))
	require.Equal(t, firstID+"\n", producer.String())
	for _, configured := range []configuration.Auditlog{first, second} {
		require.NoError(t, os.Remove(configured.IdentityFile))
	}
	for _, command := range []string{"verify", "export", "decrypt", "merge", "producer-id"} {
		t.Run(command, func(t *testing.T) {
			base := []string{"audit", command, "first", "--configuration=" + configurationPath}
			var output bytes.Buffer
			wantError := "cannot load identity"
			if command == "producer-id" {
				wantError = "cannot inspect private key"
			}
			require.ErrorContains(t, runAuditCliTestCommand(t, app, &output, base...), wantError)
			require.Empty(t, output.Bytes())
			if command != "producer-id" {
				args := append(base, "--expectedProducerId=first="+firstID)
				if command == "merge" {
					args = append(args, "second", "--expectedProducerId=second="+secondID)
				}
				require.NoError(t, runAuditCliTestCommand(t, app, &output, args...))
				if command == "verify" {
					require.Equal(t, "verified (scope: full)\n", output.String())
				} else {
					require.Contains(t, output.String(), `"name":"test.first"`)
					if command == "merge" {
						require.Contains(t, output.String(), `"name":"test.second"`)
					}
				}
			}
			require.NoFileExists(t, first.IdentityFile)
			require.NoFileExists(t, second.IdentityFile)
		})
	}
	for _, anchors := range [][]string{
		{secondID}, {"second=" + secondID}, {"invalid"}, {strings.Repeat("0", 64)}, {firstID, secondID},
	} {
		args := []string{"audit", "verify", "first", "--configuration=" + configurationPath}
		for _, anchor := range anchors {
			args = append(args, "--expectedProducerId="+anchor)
		}
		var output bytes.Buffer
		require.Error(t, runAuditCliTestCommand(t, app, &output, args...))
		require.Empty(t, output.Bytes())
	}
}

func TestAuditCommandsRejectDisabledBeforeOutputOrIdentityAccess(t *testing.T) {
	root := t.TempDir()
	configured := configuration.Auditlog{Name: "disabled", IdentityFile: filepath.Join(root, "missing-key"), Directory: filepath.Join(root, "missing-journal")}
	path := writeAuditCliTestConfiguration(t, root, configured)
	app := newAuditCliTestApplication(t)
	for _, command := range []string{"verify", "export", "decrypt", "merge"} {
		var output bytes.Buffer
		args := []string{"audit", command, "disabled", "--configuration=" + path}
		if command != "verify" {
			args = append(args, "--output="+filepath.Join(root, "must-not-create.jsonl"), "--force")
		}
		require.ErrorContains(t, runAuditCliTestCommand(t, app, &output, args...), "is disabled")
		require.Empty(t, output.Bytes())
		require.NoFileExists(t, filepath.Join(root, "must-not-create.jsonl"))
		require.NoFileExists(t, configured.IdentityFile)
		require.NoDirExists(t, configured.Directory)
	}
}

func TestAuditCommandsReadLiveCommittedCheckpoint(t *testing.T) {
	root := t.TempDir()
	var configured []configuration.Auditlog
	var recorders []bfAudit.Recorder
	for _, name := range []string{"first", "second"} {
		entry := configuration.Auditlog{Name: configuration.AuditlogName(name), Enabled: true,
			IdentityFile: filepath.Join(root, name+"-key"), Directory: filepath.Join(root, name+"-journal")}
		identity, err := bfAudit.EnsureIdentity(&entry)
		require.NoError(t, err)
		recorder, err := bfAudit.NewRecorder(&entry, identity)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, recorder.Close()) })
		configured, recorders = append(configured, entry), append(recorders, recorder)
	}
	path := writeAuditCliTestConfiguration(t, root, configured...)
	app := newAuditCliTestApplication(t)
	for _, event := range []string{"test.before-seal", "test.after-seal"} {
		for i, recorder := range recorders {
			require.NoError(t, recorder.Record(t.Context(), bfAudit.Event{Name: event + "." + configured[i].Name.String(), Flow: "confidential-flow"}))
		}
		for _, command := range []string{"verify", "export", "decrypt", "merge"} {
			var output bytes.Buffer
			args := []string{"audit", command, "first", "--configuration=" + path}
			if command == "merge" {
				args = append(args, "second")
			}
			require.NoError(t, runAuditCliTestCommand(t, app, &output, args...))
			if command != "verify" {
				require.Contains(t, output.String(), event+".first")
				if command == "merge" {
					require.Contains(t, output.String(), event+".second")
				}
				require.NotContains(t, output.String(), "confidential-flow")
			}
		}
		for _, recorder := range recorders {
			require.NoError(t, recorder.(bfAudit.SealableRecorder).Seal())
		}
	}
}

func TestAuditMergeIsChronologicalAndHonorsForce(t *testing.T) {
	root := t.TempDir()
	first := createAuditCliTestJournal(t, root, "first", "test.first")
	second := createAuditCliTestJournal(t, root, "second", "test.second")
	path := writeAuditCliTestConfiguration(t, root, first, second)
	app := newAuditCliTestApplication(t)
	args := []string{"audit", "merge", "second", "first", "--configuration=" + path}
	var output bytes.Buffer
	require.NoError(t, runAuditCliTestCommand(t, app, &output, args...))
	decoder := json.NewDecoder(&output)
	for _, name := range []string{"test.first", "test.second"} {
		var record bfAudit.VerifiedRecord
		require.NoError(t, decoder.Decode(&record))
		require.Equal(t, name, record.Event.Name)
		require.Empty(t, record.Event.Flow)
		require.Empty(t, record.Event.Reason)
	}
	var extra bfAudit.VerifiedRecord
	require.ErrorIs(t, decoder.Decode(&extra), io.EOF)
	destination := filepath.Join(root, "merged.jsonl")
	require.NoError(t, os.WriteFile(destination, []byte("preserve existing output"), 0600))
	args = append(args, "--output="+destination)
	require.Error(t, runAuditCliTestCommand(t, app, io.Discard, args...))
	requireAuditCliTestFileUnchanged(t, destination, []byte("preserve existing output"))
	require.NoError(t, runAuditCliTestCommand(t, app, io.Discard, append(args, "--force")...))
	content, err := os.ReadFile(destination)
	require.NoError(t, err)
	require.Contains(t, string(content), `"name":"test.first"`)
	require.Contains(t, string(content), `"name":"test.second"`)
}
