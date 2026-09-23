package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	exportOpts := auditExportOpts{configuration: ref, auditlog: "encrypted", output: "-", decryptionIdentityFiles: []string{privateKey}}
	var exported bytes.Buffer
	require.NoError(t, doAuditExport(&exportOpts, &exported))
	require.Contains(t, exported.String(), `"name":"test.secret"`)
	exportOpts.decryptionIdentityFiles = nil
	exported.Reset()
	require.NoError(t, doAuditExport(&exportOpts, &exported))
	require.Contains(t, exported.String(), `"name":"test.secret"`)
	exportOpts.withSensitive = true
	exported.Reset()
	require.ErrorContains(t, doAuditExport(&exportOpts, &exported), "decryption identity")
	require.Empty(t, exported.String())
	exportOpts.decryptionIdentityFiles = []string{privateKey}
	require.NoError(t, doAuditExport(&exportOpts, &exported))
	exportOpts.withSensitive = false

	var decrypted bytes.Buffer
	require.NoError(t, doAuditDecrypt(&exportOpts, &decrypted))
	require.Equal(t, exported.String(), decrypted.String())

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

	exportOpts.output = publicKey
	exportOpts.force = true
	require.ErrorContains(t, doAuditExport(&exportOpts, &bytes.Buffer{}), "must not replace encryption public key")

	exportOpts.output = privateKey
	exportOpts.force = true
	require.ErrorContains(t, doAuditExport(&exportOpts, &bytes.Buffer{}), "must not replace private key")
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
	require.NoError(t, recorder.Record(context.Background(), audit.Event{Name: eventName}))
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
