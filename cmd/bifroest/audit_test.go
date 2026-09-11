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
	require.ErrorContains(t, doAuditVerify(&verifyOpts), "requires a matching")
	verifyOpts.decryptionIdentityFiles = []string{privateKey}
	require.NoError(t, doAuditVerify(&verifyOpts))

	exportOpts := auditExportOpts{configuration: ref, auditlog: "encrypted", output: "-", decryptionIdentityFiles: []string{privateKey}}
	var exported bytes.Buffer
	require.NoError(t, doAuditExport(&exportOpts, &exported))
	require.Contains(t, exported.String(), `"name":"test.secret"`)

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
	_, err := configuredAuditJournalSource(configured, []string{"missing-decryption-key"})
	require.ErrorContains(t, err, "is disabled")
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
