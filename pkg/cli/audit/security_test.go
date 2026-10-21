package audit

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

type auditOutputProtectionFixture struct {
	configurationPath, producerID, decryptionKey string
	files                                        map[string]string
	directories                                  []string
}

func createAuditOutputProtectionFixture(t *testing.T) auditOutputProtectionFixture {
	t.Helper()
	root := t.TempDir()
	selected := createAuditCliTestJournal(t, root, "selected", "test.selected")
	other := createAuditCliTestJournal(t, root, "other", "test.other")
	recordingOnly := configuration.Auditlog{
		Name: "recording-only", IdentityFile: filepath.Join(root, "recording-signing-key"),
		Recording: configuration.AuditlogRecording{Enabled: true, Directory: filepath.Join(root, "recordings")},
	}
	_, err := bfAudit.EnsureIdentity(&recordingOnly)
	require.NoError(t, err)
	key, publicPath := createAuditCliTestKeyPair(t, root, "recipient")
	recordingOnly.EncryptionPublicKeyFile = bfcrypto.PublicKeysFile(publicPath)
	files := map[string]string{
		"selected signing identity":  selected.IdentityFile,
		"other signing identity":     other.IdentityFile,
		"recording signing identity": recordingOnly.IdentityFile,
		"decryption identity":        key,
		"encryption public key":      publicPath,
	}
	for _, name := range []string{"audit", "recording"} {
		knownHosts := filepath.Join(root, name+"-known-hosts")
		identity := filepath.Join(root, name+"-delivery-key")
		require.NoError(t, os.WriteFile(knownHosts, []byte("preserve delivery host keys\n"), 0600))
		_, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(nil, identity)
		require.NoError(t, err)
		files[name+" SFTP known hosts"], files[name+" SFTP identity"] = knownHosts, identity
		sftp := &configuration.AuditlogTargetSftp{}
		require.NoError(t, sftp.SetDefaults())
		sftp.Address, sftp.User, sftp.Directory = "archive.invalid:22", template.MustNewString("archive"), "/evidence"
		sftp.KnownHostsFile, sftp.IdentityFiles = bfcrypto.KnownHostsFile(knownHosts), []string{identity}
		targets := configuration.AuditlogTargets{{Name: "archive", V: sftp}}
		if name == "audit" {
			recordingOnly.Targets = targets
		} else {
			recordingOnly.Recording.Targets = configuration.AuditlogRecordingTargets{
				Mode: configuration.AuditlogRecordingTargetsModeCustom, Targets: targets,
			}
		}
	}
	for _, configured := range []configuration.Auditlog{selected, other} {
		producer := filepath.Join(configured.Directory, auditCliTestProducerId(t, configured.IdentityFile).String())
		files[configured.Name.String()+" head"] = filepath.Join(producer, "head.cbor")
		files[configured.Name.String()+" segment"] = auditCliTestSegment(t, configured)
	}
	sessionStorage := filepath.Join(root, "sessions")
	sealed := filepath.Join(recordingOnly.Recording.Directory, "sealed")
	for _, directory := range []string{sessionStorage, sealed} {
		require.NoError(t, os.MkdirAll(directory, 0700))
	}
	files["session state"] = filepath.Join(sessionStorage, "session-state")
	files["recording evidence"] = filepath.Join(sealed, "keep.becast")
	for _, name := range []string{"session state", "recording evidence"} {
		require.NoError(t, os.WriteFile(files[name], []byte("preserve "+name+"\n"), 0600))
	}
	path := writeAuditCliTestConfiguration(t, root, selected, other, recordingOnly)
	sshHost, _ := createAuditCliTestKeyPair(t, root, "ssh-host-identity")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &document))
	document["ssh"] = map[string]any{"keys": map[string]any{"hostKeys": []string{sshHost}}}
	encoded, err := yaml.Marshal(document)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, encoded, 0600))
	files["SSH host identity"] = sshHost
	files["configuration"] = path
	return auditOutputProtectionFixture{
		configurationPath: path, decryptionKey: key,
		producerID: auditCliTestProducerId(t, selected.IdentityFile).String(), files: files,
		directories: []string{selected.Directory, other.Directory, sessionStorage, sealed},
	}
}

func (this auditOutputProtectionFixture) args(command string, flags ...string) []string {
	return append([]string{"audit", command, "selected", "--configuration=" + this.configurationPath,
		"--expectedProducerId=" + this.producerID, "--decryptionIdentityFile=" + this.decryptionKey,
	}, flags...)
}

func auditCliTestSegment(t *testing.T, configured configuration.Auditlog) string {
	t.Helper()
	producer := filepath.Join(configured.Directory, auditCliTestProducerId(t, configured.IdentityFile).String())
	entries, err := os.ReadDir(producer)
	require.NoError(t, err)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "segment-") {
			return filepath.Join(producer, entry.Name())
		}
	}
	t.Fatal("signed test journal has no sealed segment")
	return ""
}

func requireAuditCliTestFileUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, bytes.Equal(before, after), "protected file changed: %s", path)
}

func TestAuditOutputsProtectEveryConfiguredEvidenceSource(t *testing.T) {
	fixture := createAuditOutputProtectionFixture(t)
	app := newAuditCliTestApplication(t)
	for _, command := range []string{"export", "decrypt", "merge"} {
		t.Run(command, func(t *testing.T) {
			var control bytes.Buffer
			require.NoError(t, runAuditCliTestCommand(t, app, &control, fixture.args(command)...))
			require.Contains(t, control.String(), `"name":"test.selected"`)
			for name, path := range fixture.files {
				t.Run(name, func(t *testing.T) {
					before, err := os.ReadFile(path)
					require.NoError(t, err)
					err = runAuditCliTestCommand(t, app, io.Discard, fixture.args(command, "--output="+path, "--force")...)
					require.ErrorContains(t, err, "must not")
					requireAuditCliTestFileUnchanged(t, path, before)
				})
			}
			for _, directory := range fixture.directories {
				t.Run(filepath.Base(directory), func(t *testing.T) {
					path := filepath.Join(directory, "must-not-create.jsonl")
					err := runAuditCliTestCommand(t, app, io.Discard, fixture.args(command, "--output="+path, "--force")...)
					require.ErrorContains(t, err, "must not be inside")
					require.NoFileExists(t, path)
				})
			}
		})
	}
}

func TestAuditCommandsDoNotReplaceConfigurationOrJournalAliases(t *testing.T) {
	fixture := createAuditOutputProtectionFixture(t)
	app := newAuditCliTestApplication(t)
	for _, protected := range []string{"configuration", "other segment", "SSH host identity"} {
		for _, alias := range []string{"symlink", "hardlink"} {
			t.Run(protected+"/"+alias, func(t *testing.T) {
				path := fixture.files[protected]
				before, err := os.ReadFile(path)
				require.NoError(t, err)
				output := filepath.Join(t.TempDir(), "alias")
				if alias == "symlink" {
					err = os.Symlink(path, output)
				} else {
					err = os.Link(path, output)
				}
				if err != nil {
					t.Skipf("%s unavailable on this filesystem: %v", alias, err)
				}
				for _, command := range []string{"export", "decrypt", "merge"} {
					err := runAuditCliTestCommand(t, app, io.Discard, fixture.args(command, "--output="+output, "--force")...)
					require.ErrorContains(t, err, "must not")
					requireAuditCliTestFileUnchanged(t, path, before)
					requireAuditCliTestFileUnchanged(t, output, before)
				}
			})
		}
	}
}

func TestAuditCommandsRejectProtectedStandardOutputFiles(t *testing.T) {
	fixture := createAuditOutputProtectionFixture(t)
	app := newAuditCliTestApplication(t)
	for name, path := range fixture.files {
		for _, alias := range []bool{false, true} {
			label := "direct"
			if alias {
				label = "hardlink"
			}
			t.Run(name+"/"+label, func(t *testing.T) {
				before, err := os.ReadFile(path)
				require.NoError(t, err)
				outputPath := path
				if alias {
					outputPath = filepath.Join(t.TempDir(), "stdout-alias")
					if err := os.Link(path, outputPath); err != nil {
						t.Skipf("hard links unavailable on this filesystem: %v", err)
					}
				}
				require.NoError(t, os.Chmod(path, 0600))
				for _, command := range []string{"export", "decrypt", "merge"} {
					output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_APPEND, 0)
					require.NoError(t, err)
					err = runAuditCliTestCommand(t, app, output, fixture.args(command)...)
					require.NoError(t, output.Close())
					require.ErrorContains(t, err, "must not replace")
					requireAuditCliTestFileUnchanged(t, path, before)
				}
			})
		}
	}
	for _, command := range []string{"export", "decrypt", "merge"} {
		t.Run("pipe/"+command, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
			require.NoError(t, runAuditCliTestCommand(t, app, writer, fixture.args(command)...))
			require.NoError(t, writer.Close())
			content, err := io.ReadAll(reader)
			require.NoError(t, err)
			require.Contains(t, string(content), `"name":"test.selected"`)
		})
	}
}

func TestAuditExportsDoNotPublishBeforeAllSourcesVerify(t *testing.T) {
	root := t.TempDir()
	first := createAuditCliTestJournal(t, root, "first", "test.first")
	second := createAuditCliTestJournal(t, root, "second", "test.second")
	configurationPath := writeAuditCliTestConfiguration(t, root, first, second)
	app := newAuditCliTestApplication(t)
	args := func(command, output string) []string {
		result := []string{"audit", command, "--configuration=" + configurationPath, "--with-sensitive", "--force", "--output=" + output}
		if command == "merge" {
			return append(result, "first", "second")
		}
		return append(result, "second")
	}
	for _, command := range []string{"export", "decrypt", "merge"} {
		var control bytes.Buffer
		require.NoError(t, runAuditCliTestCommand(t, app, &control, args(command, "-")...))
		require.Contains(t, control.String(), "confidential-flow-second")
	}
	segmentPath := auditCliTestSegment(t, second)
	segment, err := os.ReadFile(segmentPath)
	require.NoError(t, err)
	segment[len(segment)-1] ^= 1
	require.NoError(t, os.Chmod(segmentPath, 0600))
	require.NoError(t, os.WriteFile(segmentPath, segment, 0600))
	for _, command := range []string{"export", "decrypt", "merge"} {
		t.Run(command, func(t *testing.T) {
			var output bytes.Buffer
			require.Error(t, runAuditCliTestCommand(t, app, &output, args(command, "-")...))
			require.Empty(t, output.Bytes())
			existing := filepath.Join(t.TempDir(), "existing.jsonl")
			require.NoError(t, os.WriteFile(existing, []byte("preserve existing output"), 0600))
			require.Error(t, runAuditCliTestCommand(t, app, &output, args(command, existing)...))
			requireAuditCliTestFileUnchanged(t, existing, []byte("preserve existing output"))
			missing := filepath.Join(t.TempDir(), "must-not-create.jsonl")
			require.Error(t, runAuditCliTestCommand(t, app, &output, args(command, missing)...))
			require.NoFileExists(t, missing)
			require.Empty(t, output.Bytes())
		})
	}
}

func TestAuditExportAllowsMissingUnselectedJournal(t *testing.T) {
	root := t.TempDir()
	selected := createAuditCliTestJournal(t, root, "selected", "test.selected")
	other := createAuditCliTestJournal(t, root, "other", "test.other")
	path := writeAuditCliTestConfiguration(t, root, selected, other)
	require.NoError(t, os.RemoveAll(other.Directory))
	app := newAuditCliTestApplication(t)
	args := []string{"audit", "export", "selected", "--configuration=" + path}
	inside := filepath.Join(other.Directory, "export.jsonl")
	err := runAuditCliTestCommand(t, app, io.Discard, append(args, "--output="+inside)...)
	require.ErrorContains(t, err, "must already exist")
	require.NoDirExists(t, other.Directory)
	output := filepath.Join(root, "export.jsonl")
	require.NoError(t, runAuditCliTestCommand(t, app, io.Discard, append(args, "--output="+output)...))
	content, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Contains(t, string(content), `"name":"test.selected"`)
}
