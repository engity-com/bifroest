package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	goos "os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestAuditVerifyAndExportConfiguredJournal(t *testing.T) {
	directory := t.TempDir()
	configured := createAuditCliTestJournal(t, directory, "default", "test.export")
	ref := writeAuditCliTestConfiguration(t, directory, configured)

	require.NoError(t, doAuditVerify(&auditVerifyOpts{configuration: ref, auditlog: "default"}))
	require.ErrorContains(t, doAuditVerify(&auditVerifyOpts{configuration: ref, auditlog: "missing"}), "does not exist")

	var output bytes.Buffer
	require.NoError(t, doAuditExport(&auditExportOpts{configuration: ref, auditlog: "default", output: "-"}, &output))
	var record audit.VerifiedRecord
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record))
	require.Equal(t, "default", record.Auditlog)
	require.Equal(t, "test.export", record.Event.Name)
	require.Equal(t, audit.EventDomainSession, record.Event.Domain)
	require.Equal(t, audit.EventOutcomeSuccess, record.Event.Outcome)
	require.NotContains(t, output.String(), "confidential-flow")
	require.NotContains(t, output.String(), "internal-detail")
	require.Empty(t, record.Event.Flow)
	var publicLine map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &publicLine))
	require.Len(t, publicLine, 9)
	for _, field := range []string{"auditlog", "producerId", "segmentSequence", "segmentRecordIndex", "id", "recordedAt", "event", "previousHash", "hash"} {
		require.Contains(t, publicLine, field)
	}
	var publicEvent map[string]string
	require.NoError(t, json.Unmarshal(publicLine["event"], &publicEvent))
	require.Equal(t, map[string]string{"name": "test.export", "domain": "session", "outcome": "success"}, publicEvent)
	require.FileExists(t, configured.IdentityFile)

	require.NoError(t, goos.Remove(configured.IdentityFile))
	require.ErrorContains(t, doAuditVerify(&auditVerifyOpts{configuration: ref, auditlog: "default"}), "cannot load identity")
	require.NoFileExists(t, configured.IdentityFile)
}

func TestAuditMergeIsChronologicalAndOutputIsProtected(t *testing.T) {
	directory := t.TempDir()
	first := createAuditCliTestJournal(t, directory, "first", "test.first")
	second := createAuditCliTestJournal(t, directory, "second", "test.second")
	ref := writeAuditCliTestConfiguration(t, directory, first, second)
	opts := auditMergeOpts{configuration: ref, auditlogs: []string{"second", "first"}, output: "-"}

	var output bytes.Buffer
	require.NoError(t, doAuditMerge(&opts, &output))
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, 2)
	var firstRecord, secondRecord audit.VerifiedRecord
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &firstRecord))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &secondRecord))
	require.Equal(t, "test.first", firstRecord.Event.Name)
	require.Equal(t, "test.second", secondRecord.Event.Name)
	require.NotContains(t, output.String(), "confidential-flow")
	opts.withSensitive = true
	output.Reset()
	require.NoError(t, doAuditMerge(&opts, &output))
	require.Contains(t, output.String(), "confidential-flow-first")
	require.Contains(t, output.String(), "confidential-flow-second")
	opts.withSensitive = false

	outputPath := filepath.Join(directory, "merged.jsonl")
	opts.output = outputPath
	require.NoError(t, doAuditMerge(&opts, &bytes.Buffer{}))
	require.Error(t, doAuditMerge(&opts, &bytes.Buffer{}))
	opts.force = true
	require.NoError(t, doAuditMerge(&opts, &bytes.Buffer{}))

	opts.output = filepath.Join(first.Journal.Directory, "must-not-overwrite.jsonl")
	require.ErrorContains(t, doAuditMerge(&opts, &bytes.Buffer{}), "must not be inside")
}

func TestAuditOutputsProtectEveryEnabledConfiguredAuditlog(t *testing.T) {
	directory := t.TempDir()
	selected := createAuditCliTestJournal(t, directory, "selected", "test.selected")
	other := createAuditCliTestJournal(t, directory, "other", "test.other")
	ref := writeAuditCliTestConfiguration(t, directory, selected, other)

	commands := map[string]func(string) error{
		"export": func(output string) error {
			return doAuditExport(&auditExportOpts{configuration: ref, auditlog: "selected", output: output, force: true}, &bytes.Buffer{})
		},
		"decrypt": func(output string) error {
			return doAuditDecrypt(&auditExportOpts{configuration: ref, auditlog: "selected", output: output, force: true}, &bytes.Buffer{})
		},
		"merge": func(output string) error {
			return doAuditMerge(&auditMergeOpts{configuration: ref, auditlogs: []string{"selected"}, output: output, force: true}, &bytes.Buffer{})
		},
	}
	for name, command := range commands {
		t.Run(name+" rejects other identity", func(t *testing.T) {
			require.ErrorContains(t, command(other.IdentityFile), "must not replace private key")
			require.FileExists(t, other.IdentityFile)
		})
		t.Run(name+" rejects other journal", func(t *testing.T) {
			output := filepath.Join(other.Journal.Directory, name+".jsonl")
			require.ErrorContains(t, command(output), "must not be inside")
			require.NoFileExists(t, output)
		})
	}
}

func TestAuditCommandsDoNotReplaceConfiguration(t *testing.T) {
	directory := t.TempDir()
	configured := createAuditCliTestJournal(t, directory, "selected", "test.selected")
	ref := writeAuditCliTestConfiguration(t, directory, configured)
	configPath := ref.GetFilename()
	original, err := goos.ReadFile(configPath)
	require.NoError(t, err)
	commands := map[string]func(string) error{
		"export": func(path string) error {
			return doAuditExport(&auditExportOpts{configuration: ref, auditlog: configured.Name, output: path, force: true}, io.Discard)
		},
		"decrypt": func(path string) error {
			return doAuditDecrypt(&auditExportOpts{configuration: ref, auditlog: configured.Name, output: path, force: true}, io.Discard)
		},
		"merge": func(path string) error {
			return doAuditMerge(&auditMergeOpts{configuration: ref, auditlogs: []string{string(configured.Name)}, output: path, force: true}, io.Discard)
		},
	}
	for name, createAlias := range map[string]func(string) error{
		"direct":   func(string) error { return nil },
		"symlink":  func(path string) error { return goos.Symlink(configPath, path) },
		"hardlink": func(path string) error { return goos.Link(configPath, path) },
	} {
		t.Run(name, func(t *testing.T) {
			path := configPath
			if name != "direct" {
				path = filepath.Join(directory, name+"-config.yaml")
				if err := createAlias(path); err != nil {
					t.Skipf("cannot create %s on this filesystem: %v", name, err)
				}
			}
			for commandName, command := range commands {
				t.Run(commandName, func(t *testing.T) {
					require.ErrorContains(t, command(path), "must not replace configuration file")
					content, err := goos.ReadFile(configPath)
					require.NoError(t, err)
					require.Equal(t, original, content)
					aliasContent, err := goos.ReadFile(path)
					require.NoError(t, err)
					require.Equal(t, original, aliasContent)
				})
			}
		})
	}
}

func TestAuditCommandsRejectProtectedStandardOutputFiles(t *testing.T) {
	directory := t.TempDir()
	selected := createAuditCliTestJournal(t, directory, "selected", "test.selected")
	other := createAuditCliTestJournal(t, directory, "other", "test.other")
	ref := writeAuditCliTestConfiguration(t, directory, selected, other)
	ageKey := filepath.Join(directory, "age-key")
	require.NoError(t, doKeyGenerate(ageKey, filepath.Join(directory, "age-key.pub")))
	for _, path := range []string{selected.IdentityFile, other.IdentityFile, ageKey} {
		require.NoError(t, goos.Chmod(path, 0600))
	}
	producer := filepath.Join(selected.Journal.Directory, auditCliTestProducerId(t, selected.IdentityFile).String())
	entries, err := goos.ReadDir(producer)
	require.NoError(t, err)
	var segment string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "segment-") {
			segment = filepath.Join(producer, entry.Name())
			break
		}
	}
	require.NotEmpty(t, segment)
	segmentAlias := filepath.Join(directory, "segment-alias")
	otherProducer := filepath.Join(other.Journal.Directory, auditCliTestProducerId(t, other.IdentityFile).String())
	paths := map[string]string{
		"configuration": ref.GetFilename(),
		"signing key":   selected.IdentityFile,
		"other key":     other.IdentityFile,
		"age key":       ageKey,
		"head":          filepath.Join(producer, "head.cbor"),
		"segment":       segment,
		"other head":    filepath.Join(otherProducer, "head.cbor"),
	}
	if err := goos.Link(segment, segmentAlias); err == nil {
		paths["segment hardlink"] = segmentAlias
	}
	for _, path := range []string{paths["head"], paths["segment"], paths["other head"]} {
		require.NoError(t, goos.Chmod(path, 0600))
	}
	commands := map[string]func(io.Writer) error{
		"export": func(stdout io.Writer) error {
			return doAuditExport(&auditExportOpts{configuration: ref, auditlog: selected.Name, output: "-", decryptionIdentityFiles: []string{ageKey}}, stdout)
		},
		"decrypt": func(stdout io.Writer) error {
			return doAuditDecrypt(&auditExportOpts{configuration: ref, auditlog: selected.Name, output: "-", decryptionIdentityFiles: []string{ageKey}}, stdout)
		},
		"merge": func(stdout io.Writer) error {
			return doAuditMerge(&auditMergeOpts{configuration: ref, auditlogs: []string{string(selected.Name)}, output: "-", decryptionIdentityFiles: []string{ageKey}}, stdout)
		},
	}
	for pathName, path := range paths {
		t.Run(pathName, func(t *testing.T) {
			original, err := goos.ReadFile(path)
			require.NoError(t, err)
			for commandName, command := range commands {
				t.Run(commandName, func(t *testing.T) {
					stdout, err := goos.OpenFile(path, goos.O_WRONLY|goos.O_APPEND, 0)
					require.NoError(t, err)
					commandErr := command(stdout)
					require.NoError(t, stdout.Close())
					require.ErrorContains(t, commandErr, "must not replace")
					content, err := goos.ReadFile(path)
					require.NoError(t, err)
					require.Equal(t, original, content)
				})
			}
		})
	}
	for commandName, command := range commands {
		t.Run("pipe "+commandName, func(t *testing.T) {
			reader, writer, err := goos.Pipe()
			require.NoError(t, err)
			require.NoError(t, command(writer))
			require.NoError(t, writer.Close())
			content, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.NoError(t, reader.Close())
			require.Contains(t, string(content), `"name":"test.selected"`)
		})
	}
	if _, err := goos.Stat(segmentAlias); err == nil {
		original, err := goos.ReadFile(segment)
		require.NoError(t, err)
		for commandName, command := range map[string]func() error{
			"export": func() error {
				return doAuditExport(&auditExportOpts{configuration: ref, auditlog: selected.Name, output: segmentAlias, force: true}, io.Discard)
			},
			"decrypt": func() error {
				return doAuditDecrypt(&auditExportOpts{configuration: ref, auditlog: selected.Name, output: segmentAlias, force: true}, io.Discard)
			},
			"merge": func() error {
				return doAuditMerge(&auditMergeOpts{configuration: ref, auditlogs: []string{string(selected.Name)}, output: segmentAlias, force: true}, io.Discard)
			},
		} {
			t.Run("output hardlink "+commandName, func(t *testing.T) {
				require.ErrorContains(t, command(), "must not replace journal file")
				content, err := goos.ReadFile(segment)
				require.NoError(t, err)
				require.Equal(t, original, content)
			})
		}
	}
}

func TestAuditOutputProtectsSessionStorageAndSftpFiles(t *testing.T) {
	directory := t.TempDir()
	sessionStorage := filepath.Join(directory, "sessions")
	require.NoError(t, goos.Mkdir(sessionStorage, 0700))
	recordingDirectory := filepath.Join(directory, "recordings")
	require.NoError(t, goos.Mkdir(recordingDirectory, 0700))
	knownHosts := filepath.Join(directory, "known-hosts")
	identity := filepath.Join(directory, "archive-key")
	recordingKnownHosts := filepath.Join(directory, "recording-known-hosts")
	recordingIdentity := filepath.Join(directory, "recording-archive-key")
	require.NoError(t, goos.WriteFile(knownHosts, []byte("host key"), 0600))
	require.NoError(t, goos.WriteFile(identity, []byte("private key"), 0600))
	require.NoError(t, goos.WriteFile(recordingKnownHosts, []byte("host key"), 0600))
	require.NoError(t, goos.WriteFile(recordingIdentity, []byte("private key"), 0600))
	conf := &configuration.Configuration{
		Session: configuration.Session{V: &configuration.SessionFs{Storage: sessionStorage}},
		Auditlogs: configuration.Auditlogs{{
			Name:    "security",
			Enabled: true,
			Journal: configuration.AuditlogJournal{Directory: filepath.Join(directory, "journal")},
			Recording: configuration.AuditlogRecording{
				Enabled:   true,
				Directory: recordingDirectory,
				Targets: configuration.AuditlogRecordingTargets{
					Mode: configuration.AuditlogRecordingTargetsModeCustom,
					Targets: configuration.AuditlogTargets{{
						Name: "recording-archive",
						V: &configuration.AuditlogTargetSftp{
							KnownHostsFile: bfcrypto.KnownHostsFile(recordingKnownHosts),
							IdentityFiles:  []string{recordingIdentity},
						},
					}},
				},
			},
			Targets: configuration.AuditlogTargets{{
				Name: "archive",
				V: &configuration.AuditlogTargetSftp{
					KnownHostsFile: bfcrypto.KnownHostsFile(knownHosts),
					IdentityFiles:  []string{identity},
				},
			}},
		}},
	}

	require.ErrorContains(t, ensureAuditOutputSafe(filepath.Join(sessionStorage, "export.jsonl"), conf), "must not be inside session storage")
	require.ErrorContains(t, ensureAuditOutputSafe(filepath.Join(recordingDirectory, "export.jsonl"), conf), "must not be inside auditlog \"security\" recording directory")
	require.ErrorContains(t, ensureAuditOutputSafe(knownHosts, conf), "must not replace SFTP known-hosts file")
	require.ErrorContains(t, ensureAuditOutputSafe(identity, conf), "must not replace private key")
	require.ErrorContains(t, ensureAuditOutputSafe(recordingKnownHosts, conf), "must not replace Recording SFTP known-hosts file")
	require.ErrorContains(t, ensureAuditOutputSafe(recordingIdentity, conf), "must not replace private key")

	conf.Auditlogs[0].Recording.Enabled = false
	require.NoError(t, ensureAuditOutputSafe(recordingKnownHosts, conf))
	require.NoError(t, ensureAuditOutputSafe(recordingIdentity, conf))
}

func TestAuditExportAllowsMissingUnselectedJournal(t *testing.T) {
	directory := t.TempDir()
	selected := createAuditCliTestJournal(t, directory, "selected", "test.selected")
	other := createAuditCliTestJournal(t, directory, "other", "test.other")
	ref := writeAuditCliTestConfiguration(t, directory, selected, other)
	require.NoError(t, goos.RemoveAll(other.Journal.Directory))
	insideOtherJournal := filepath.Join(other.Journal.Directory, "export.jsonl")
	require.ErrorContains(t, doAuditExport(&auditExportOpts{
		configuration: ref,
		auditlog:      selected.Name,
		output:        insideOtherJournal,
	}, &bytes.Buffer{}), "must already exist")
	require.NoDirExists(t, other.Journal.Directory)

	output := filepath.Join(directory, "export.jsonl")

	require.NoError(t, doAuditExport(&auditExportOpts{
		configuration: ref,
		auditlog:      selected.Name,
		output:        output,
	}, &bytes.Buffer{}))
	require.FileExists(t, output)
}

func TestAuditCommandsDecryptEncryptedJournal(t *testing.T) {
	directory := t.TempDir()
	privateKey := filepath.Join(directory, "encryption-key")
	publicKey := filepath.Join(directory, "encryption-key.pub")
	require.NoError(t, doKeyGenerate(privateKey, publicKey))
	public, err := goos.ReadFile(publicKey)
	require.NoError(t, err)
	configured := createAuditCliTestJournalWithEncryption(t, directory, "encrypted", "test.secret", bfcrypto.PublicKeys(strings.TrimSpace(string(public))))
	configured.EncryptionPublicKey = ""
	configured.EncryptionPublicKeyFile = bfcrypto.PublicKeysFile(publicKey)
	plain := createAuditCliTestJournal(t, directory, "plain", "test.plain")
	ref := writeAuditCliTestConfiguration(t, directory, configured, plain)

	verifyOpts := auditVerifyOpts{configuration: ref, auditlog: "encrypted"}
	require.NoError(t, doAuditVerify(&verifyOpts))
	verifyOpts.decryptionIdentityFiles = []string{privateKey}
	require.NoError(t, doAuditVerify(&verifyOpts))
	wrongKey := filepath.Join(directory, "wrong-decryption-key")
	require.NoError(t, doKeyGenerate(wrongKey, filepath.Join(directory, "wrong-decryption-key.pub")))
	verifyOpts.decryptionIdentityFiles = []string{wrongKey}
	require.Error(t, doAuditVerify(&verifyOpts))

	exportOpts := auditExportOpts{configuration: ref, auditlog: "encrypted", output: "-", decryptionIdentityFiles: []string{privateKey}}
	var exported bytes.Buffer
	require.NoError(t, doAuditExport(&exportOpts, &exported))
	require.Contains(t, exported.String(), `"name":"test.secret"`)
	require.NotContains(t, exported.String(), "confidential-flow")
	exportOpts.decryptionIdentityFiles = nil
	exported.Reset()
	require.NoError(t, doAuditExport(&exportOpts, &exported))
	require.Contains(t, exported.String(), `"name":"test.secret"`)
	require.NotContains(t, exported.String(), "confidential-flow")
	redactedExport := exported.String()
	for _, unusedIdentity := range []string{wrongKey, filepath.Join(directory, "missing-decryption-key")} {
		exportOpts.decryptionIdentityFiles = []string{unusedIdentity}
		exported.Reset()
		require.NoError(t, doAuditExport(&exportOpts, &exported))
		require.Equal(t, redactedExport, exported.String())
	}
	exportOpts.withSensitive = true
	exported.Reset()
	require.ErrorContains(t, doAuditExport(&exportOpts, &exported), "decryption identity")
	require.Empty(t, exported.String())
	exportOpts.decryptionIdentityFiles = []string{privateKey}
	require.NoError(t, doAuditExport(&exportOpts, &exported))
	require.Contains(t, exported.String(), "confidential-flow-encrypted")
	exportOpts.withSensitive = false

	var decrypted bytes.Buffer
	require.NoError(t, doAuditDecrypt(&exportOpts, &decrypted))
	require.Equal(t, redactedExport, decrypted.String())
	require.NotContains(t, decrypted.String(), "confidential-flow")
	exportOpts.decryptionIdentityFiles = []string{filepath.Join(directory, "missing-decryption-key")}
	decrypted.Reset()
	require.NoError(t, doAuditDecrypt(&exportOpts, &decrypted))
	require.Equal(t, redactedExport, decrypted.String())
	exportOpts.decryptionIdentityFiles = []string{privateKey}
	exportOpts.withSensitive = true
	decrypted.Reset()
	require.NoError(t, doAuditDecrypt(&exportOpts, &decrypted))
	require.Contains(t, decrypted.String(), "confidential-flow-encrypted")
	exportOpts.withSensitive = false

	mergeOpts := auditMergeOpts{
		configuration:           ref,
		auditlogs:               []string{"encrypted", "plain"},
		output:                  "-",
		decryptionIdentityFiles: []string{privateKey},
	}
	var merged bytes.Buffer
	require.NoError(t, doAuditMerge(&mergeOpts, &merged))
	require.Contains(t, merged.String(), `"name":"test.secret"`)
	require.Contains(t, merged.String(), `"name":"test.plain"`)
	require.NotContains(t, merged.String(), "confidential-flow")
	mergeOpts.decryptionIdentityFiles = []string{filepath.Join(directory, "missing-decryption-key")}
	merged.Reset()
	require.NoError(t, doAuditMerge(&mergeOpts, &merged))
	require.Contains(t, merged.String(), `"name":"test.secret"`)
	require.NotContains(t, merged.String(), "confidential-flow")
	mergeOpts.decryptionIdentityFiles = []string{privateKey}
	mergeOpts.withSensitive = true
	merged.Reset()
	require.NoError(t, doAuditMerge(&mergeOpts, &merged))
	require.Contains(t, merged.String(), "confidential-flow-encrypted")
	require.Contains(t, merged.String(), "confidential-flow-plain")
	mergeOpts.decryptionIdentityFiles = []string{wrongKey}
	merged.Reset()
	require.Error(t, doAuditMerge(&mergeOpts, &merged))
	require.Empty(t, merged.String())

	exportOpts.output = publicKey
	exportOpts.force = true
	require.ErrorContains(t, doAuditExport(&exportOpts, &bytes.Buffer{}), "must not replace encryption public key")

	exportOpts.output = privateKey
	exportOpts.force = true
	require.ErrorContains(t, doAuditExport(&exportOpts, &bytes.Buffer{}), "must not replace private key")
}

func TestAuditExportsDoNotPublishBeforeAllSourcesVerify(t *testing.T) {
	directory := t.TempDir()
	first := createAuditCliTestJournal(t, directory, "first", "test.first")
	second := createAuditCliTestJournal(t, directory, "second", "test.second")
	ref := writeAuditCliTestConfiguration(t, directory, first, second)
	producer := filepath.Join(second.Journal.Directory, auditCliTestProducerId(t, second.IdentityFile).String())
	entries, err := goos.ReadDir(producer)
	require.NoError(t, err)
	var segmentPath string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "segment-") {
			segmentPath = filepath.Join(producer, entry.Name())
			break
		}
	}
	require.NotEmpty(t, segmentPath)
	segment, err := goos.ReadFile(segmentPath)
	require.NoError(t, err)
	segment[len(segment)-1] ^= 1
	require.NoError(t, goos.Chmod(segmentPath, 0600))
	require.NoError(t, goos.WriteFile(segmentPath, segment, 0600))

	output := filepath.Join(directory, "protected.jsonl")
	require.NoError(t, goos.WriteFile(output, []byte("untouched"), 0600))
	for name, run := range map[string]func(string, *bytes.Buffer) error{
		"export": func(path string, target *bytes.Buffer) error {
			return doAuditExport(&auditExportOpts{configuration: ref, auditlog: "second", output: path, force: true, withSensitive: true}, target)
		},
		"decrypt": func(path string, target *bytes.Buffer) error {
			return doAuditDecrypt(&auditExportOpts{configuration: ref, auditlog: "second", output: path, force: true, withSensitive: true}, target)
		},
		"merge": func(path string, target *bytes.Buffer) error {
			return doAuditMerge(&auditMergeOpts{configuration: ref, auditlogs: []string{"first", "second"}, output: path, force: true, withSensitive: true}, target)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			require.Error(t, run("-", &stdout))
			require.Empty(t, stdout.String())
			require.Error(t, run(output, &bytes.Buffer{}))
			content, err := goos.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, "untouched", string(content))
		})
	}
}

func TestBoundedAuditOutputRejectsOversizedWrite(t *testing.T) {
	output := boundedAuditOutput{limit: 4}
	written, err := output.Write([]byte("12345"))
	require.Zero(t, written)
	require.ErrorContains(t, err, "exceeds 4 bytes")
	require.Empty(t, output.Bytes())
}

func TestLoadAuditPrivateKeyRejectsNonRegularAndOversizedFiles(t *testing.T) {
	directory := t.TempDir()
	_, err := loadAuditPrivateKey(directory)
	require.ErrorContains(t, err, "not a regular file")

	oversized := filepath.Join(directory, "oversized-key")
	file, err := goos.Create(oversized)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(maxAuditPrivateKeySize+1))
	require.NoError(t, file.Close())
	_, err = loadAuditPrivateKey(oversized)
	require.ErrorContains(t, err, "exceeds")
}

func TestConfiguredAuditJournalSourceRejectsDisabledBeforeFileAccess(t *testing.T) {
	configured := &configuration.Auditlog{
		Name:                    "disabled",
		IdentityFile:            "missing-signing-key",
		EncryptionPublicKeyFile: "missing-encryption-key.pub",
	}
	_, err := configuredAuditJournalSource(configured, []string{"missing-decryption-key"}, audit.ProducerId{})
	require.ErrorContains(t, err, "is disabled")
}

func TestAuditCommandsUseExplicitProducerTrustAnchorsWithoutSigningKeys(t *testing.T) {
	directory := t.TempDir()
	first := createAuditCliTestJournal(t, directory, "first", "test.first")
	second := createAuditCliTestJournal(t, directory, "second", "test.second")
	firstProducerId := auditCliTestProducerId(t, first.IdentityFile)
	secondProducerId := auditCliTestProducerId(t, second.IdentityFile)
	ref := writeAuditCliTestConfiguration(t, directory, first, second)
	require.NoError(t, goos.Remove(first.IdentityFile))
	require.NoError(t, goos.Remove(second.IdentityFile))

	require.ErrorContains(t, doAuditVerify(&auditVerifyOpts{configuration: ref, auditlog: "first"}), "cannot load identity")
	firstAnchor := "first=" + firstProducerId.String()
	require.NoError(t, doAuditVerify(&auditVerifyOpts{
		configuration:       ref,
		auditlog:            "first",
		expectedProducerIds: []string{firstAnchor},
	}))

	var exported bytes.Buffer
	require.NoError(t, doAuditExport(&auditExportOpts{
		configuration:       ref,
		auditlog:            "first",
		output:              "-",
		expectedProducerIds: []string{firstAnchor},
	}, &exported))
	require.Contains(t, exported.String(), `"name":"test.first"`)

	var decrypted bytes.Buffer
	require.NoError(t, doAuditDecrypt(&auditExportOpts{
		configuration:       ref,
		auditlog:            "first",
		output:              "-",
		expectedProducerIds: []string{firstAnchor},
	}, &decrypted))
	require.Equal(t, exported.String(), decrypted.String())

	var merged bytes.Buffer
	require.NoError(t, doAuditMerge(&auditMergeOpts{
		configuration: ref,
		auditlogs:     []string{"first", "second"},
		output:        "-",
		expectedProducerIds: []string{
			firstAnchor,
			"second=" + secondProducerId.String(),
		},
	}, &merged))
	require.Contains(t, merged.String(), `"name":"test.first"`)
	require.Contains(t, merged.String(), `"name":"test.second"`)

	require.ErrorContains(t, doAuditVerify(&auditVerifyOpts{
		configuration:       ref,
		auditlog:            "first",
		expectedProducerIds: []string{"first=" + secondProducerId.String()},
	}), "instead of expected producer")
	require.ErrorContains(t, doAuditVerify(&auditVerifyOpts{
		configuration:       ref,
		auditlog:            "first",
		expectedProducerIds: []string{"second=" + secondProducerId.String()},
	}), "unselected auditlog")
}

func TestAuditTrustAnchorsRejectMalformedDuplicateAndZeroValues(t *testing.T) {
	selected := []*configuration.Auditlog{{Name: "default"}}
	zero := strings.Repeat("0", 64)
	for _, values := range [][]string{
		{"missing-separator"},
		{"default=invalid"},
		{"default=" + zero},
		{"default=" + strings.Repeat("1", 64), "default=" + strings.Repeat("2", 64)},
	} {
		_, err := parseAuditTrustAnchors(values, selected)
		require.Error(t, err)
	}
}

func TestAuditNativeSourceAllowsOuterVerificationWithoutDecryptionKey(t *testing.T) {
	directory := t.TempDir()
	privateKey := filepath.Join(directory, "encryption-key")
	publicKey := filepath.Join(directory, "encryption-key.pub")
	require.NoError(t, doKeyGenerate(privateKey, publicKey))
	public, err := goos.ReadFile(publicKey)
	require.NoError(t, err)
	configured := createAuditCliTestJournalWithEncryption(t, directory, "encrypted", "test.secret", bfcrypto.PublicKeys(strings.TrimSpace(string(public))))
	producerId := auditCliTestProducerId(t, configured.IdentityFile)
	require.NoError(t, goos.Remove(configured.IdentityFile))
	source, err := configuredAuditJournalSource(&configured, nil, producerId)
	require.NoError(t, err)
	require.Equal(t, producerId, source.ExpectedProducerId)
	require.NotEmpty(t, source.ExpectedEncryptionRecipient)
	require.Empty(t, source.DecryptionIdentities)
}

func TestAuditExportAndDecryptRejectDisabledBeforeOutputAccess(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "output.jsonl")
	var ref configuration.Ref
	ref.Get().Auditlogs = configuration.Auditlogs{{
		Name:                    "disabled",
		IdentityFile:            filepath.Join(directory, "missing-signing-key"),
		EncryptionPublicKeyFile: bfcrypto.PublicKeysFile(filepath.Join(directory, "missing-encryption-key.pub")),
		Journal:                 configuration.AuditlogJournal{Directory: filepath.Join(directory, "missing-journal")},
	}}
	opts := auditExportOpts{configuration: ref, auditlog: "disabled", output: output, force: true}
	require.ErrorContains(t, doAuditExport(&opts, &bytes.Buffer{}), "is disabled")
	require.NoFileExists(t, output)
	require.ErrorContains(t, doAuditDecrypt(&opts, &bytes.Buffer{}), "is disabled")
	require.NoFileExists(t, output)
}

func createAuditCliTestJournal(t *testing.T, parent, name, eventName string) configuration.Auditlog {
	return createAuditCliTestJournalWithEncryption(t, parent, name, eventName, "")
}

func createAuditCliTestJournalWithEncryption(t *testing.T, parent, name, eventName string, encryptionPublicKey bfcrypto.PublicKeys) configuration.Auditlog {
	t.Helper()
	configured := configuration.Auditlog{
		Name:                configuration.AuditlogName(name),
		Enabled:             true,
		IdentityFile:        filepath.Join(parent, name+"-key"),
		EncryptionPublicKey: encryptionPublicKey,
		Journal: configuration.AuditlogJournal{
			Directory: filepath.Join(parent, name+"-journal"),
		},
	}
	identity, err := audit.EnsureIdentity(&configured)
	require.NoError(t, err)
	recorder, err := audit.NewRecorder(&configured, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), audit.Event{
		Name: eventName, Domain: audit.EventDomainSession, Outcome: audit.EventOutcomeSuccess,
		Flow: "confidential-flow-" + name, Reason: "internal-detail",
	}))
	require.NoError(t, recorder.Close())
	return configured
}

func auditCliTestProducerId(t *testing.T, identityFile string) audit.ProducerId {
	t.Helper()
	privateKey, err := loadAuditPrivateKey(identityFile)
	require.NoError(t, err)
	identity, err := audit.NewIdentity(privateKey)
	require.NoError(t, err)
	return identity.ProducerId()
}

func writeAuditCliTestConfiguration(t *testing.T, directory string, auditlogs ...configuration.Auditlog) configuration.Ref {
	t.Helper()
	var raw strings.Builder
	raw.WriteString("auditlog:\n")
	for _, configured := range auditlogs {
		_, _ = fmt.Fprintf(&raw, "  - name: %s\n    enabled: true\n    identityFile: %s\n    journal:\n      directory: %s\n",
			configured.Name,
			filepath.ToSlash(configured.IdentityFile),
			filepath.ToSlash(configured.Journal.Directory),
		)
		if !configured.EncryptionPublicKey.IsZero() {
			_, _ = fmt.Fprintf(&raw, "    encryptionPublicKey: %q\n", string(configured.EncryptionPublicKey))
		}
		if !configured.EncryptionPublicKeyFile.IsZero() {
			_, _ = fmt.Fprintf(&raw, "    encryptionPublicKeyFile: %q\n", string(configured.EncryptionPublicKeyFile))
		}
	}
	_, _ = fmt.Fprintf(&raw, "flows:\n  - name: flow\n    auditlog: %s\n    authorization:\n      type: simple\n    environment:\n      type: dummy\n", auditlogs[0].Name)
	path := filepath.Join(directory, "configuration.yaml")
	require.NoError(t, goos.WriteFile(path, []byte(raw.String()), 0600))
	var ref configuration.Ref
	require.NoError(t, ref.Set(path))
	return ref
}
