package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestAuditlog_UnmarshalYAML(t *testing.T) {
	runUnmarshalYamlTests(t,
		unmarshalYamlTestCase[Auditlog]{
			name: "defaults",
			yaml: `{}`,
			expected: Auditlog{
				Name:             DefaultAuditlogName,
				FailurePolicy:    DefaultAuditlogFailurePolicy,
				IdentityFile:     DefaultAuditlogIdentityFile,
				Directory:        DefaultAuditlogJournalDirectory,
				MinimumFreeBytes: DefaultAuditlogJournalMinimumFreeBytes,
				Recording:        expectedDefaultAuditlogRecording(),
			},
		},
		unmarshalYamlTestCase[Auditlog]{
			name: "customized",
			yaml: `
failurePolicy: bestEffort
identityFile: "  custom-audit-key  "
directory: "  custom-journal  "`,
			expected: Auditlog{
				Name:             DefaultAuditlogName,
				FailurePolicy:    AuditlogFailurePolicyBestEffort,
				IdentityFile:     "custom-audit-key",
				Directory:        "custom-journal",
				MinimumFreeBytes: DefaultAuditlogJournalMinimumFreeBytes,
				Recording:        expectedDefaultAuditlogRecording(),
			},
		},
		unmarshalYamlTestCase[Auditlog]{
			name:          "missing-identity-file",
			yaml:          `identityFile: " "`,
			expectedError: `[identityFile] required but absent`,
		},
		unmarshalYamlTestCase[Auditlog]{
			name:          "missing-directory",
			yaml:          `directory: " "`,
			expectedError: `[directory] required but absent`,
		},
		unmarshalYamlTestCase[Auditlog]{
			name:          "unknown-field",
			yaml:          `unknown: true`,
			expectedError: `field unknown not found`,
		},
		unmarshalYamlTestCase[Auditlog]{
			name: "nested-journal-rejected",
			yaml: `journal:
  directory: journal`,
			expectedError: `field journal not found`,
		},
		unmarshalYamlTestCase[Auditlog]{
			name: "explicit-reserve",
			yaml: "minimumFreeBytes: 1048576",
			expected: Auditlog{
				Name:          DefaultAuditlogName,
				FailurePolicy: DefaultAuditlogFailurePolicy, IdentityFile: DefaultAuditlogIdentityFile,
				Directory: DefaultAuditlogJournalDirectory, MinimumFreeBytes: 1048576,
				Recording: expectedDefaultAuditlogRecording(),
			},
		},
		unmarshalYamlTestCase[Auditlog]{
			name: "explicit-zero-reserve",
			yaml: "minimumFreeBytes: 0",
			expected: Auditlog{
				Name:          DefaultAuditlogName,
				FailurePolicy: DefaultAuditlogFailurePolicy, IdentityFile: DefaultAuditlogIdentityFile,
				Directory: DefaultAuditlogJournalDirectory, MinimumFreeBytes: 0,
				Recording: expectedDefaultAuditlogRecording(),
			},
		},
	)
}

func TestAuditlogsDefaultAndExplicitEntries(t *testing.T) {
	var absent Auditlogs
	require.NoError(t, absent.SetDefaults())
	require.Empty(t, absent)

	var empty Auditlogs
	require.NoError(t, yaml.Unmarshal([]byte(`{}`), &empty))
	require.Empty(t, empty)
	require.Error(t, yaml.Unmarshal([]byte(`[]`), &empty))

	var configured Auditlogs
	require.NoError(t, yaml.Unmarshal([]byte(`
default: {}
security:
  identityFile: security-key
  directory: security-journal
`), &configured))
	require.Len(t, configured, 2)
	require.Equal(t, AuditlogName("security"), configured[1].Name)
}

func TestAuditlogsRejectConflicts(t *testing.T) {
	duplicateNames := Auditlogs{{Name: "duplicate"}, {Name: "duplicate"}}
	require.ErrorContains(t, duplicateNames.Validate(), "duplicates")

	duplicatePaths := Auditlogs{
		{Name: "first", IdentityFile: "key", Directory: "journal-1"},
		{Name: "second", IdentityFile: "key", Directory: "journal-2"},
	}
	require.ErrorContains(t, duplicatePaths.Validate(), "identityFile")
	duplicatePaths[1].IdentityFile = "other-key"
	duplicatePaths[1].Directory = duplicatePaths[0].Directory
	require.ErrorContains(t, duplicatePaths.Validate(), "[1][directory] duplicates auditlog [0][directory]")

	overlappingJournals := Auditlogs{
		{Name: "first", IdentityFile: "key-1", Directory: "journals"},
		{Name: "second", IdentityFile: "key-2", Directory: "journals/second"},
	}
	require.ErrorContains(t, overlappingJournals.Validate(), "[1][directory] overlaps auditlog [0][directory]")

	identityInsideJournal := Auditlogs{
		{Name: "first", IdentityFile: "journals/first-key", Directory: "journal-1"},
		{Name: "second", IdentityFile: "key-2", Directory: "journals"},
	}
	require.ErrorContains(t, identityInsideJournal.Validate(), "[0][identityFile] is located inside auditlog [1][directory]")

	journalBelowIdentity := Auditlogs{{
		Name:         "first",
		IdentityFile: "key",
		Directory:    "key/journal",
	}}
	require.ErrorContains(t, journalBelowIdentity.Validate(), "[0][directory] is located below auditlog [0][identityFile]")

	overlappingIdentities := Auditlogs{
		{Name: "first", IdentityFile: "keys", Directory: "journal-1"},
		{Name: "second", IdentityFile: "keys/second", Directory: "journal-2"},
	}
	require.ErrorContains(t, overlappingIdentities.Validate(), "identityFile] overlaps")
}

func TestAuditlogNameValidationAlsoAppliesProgrammatically(t *testing.T) {
	auditlogs := Auditlogs{{
		Name:         "invalid/name",
		IdentityFile: "key",
		Directory:    "journal",
	}}
	require.ErrorContains(t, auditlogs.Validate(), "illegal auditlog name")

	flow := Flow{Name: "flow", Auditlog: "invalid/name"}
	require.ErrorContains(t, flow.Validate(), "illegal auditlog name")
	require.ErrorContains(t, AuditlogName(strings.Repeat("a", maximumAuditlogNameLength+1)).Validate(), "exceeds")
}

func TestAuditlogEncryptionPublicKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPublic, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic)))

	var configured Auditlog
	require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf("encryptionPublicKey: %s\n", authorized)), &configured))
	require.Equal(t, crypto.PublicKeys(authorized), configured.EncryptionPublicKey)

	var multiple Auditlog
	err = yaml.Unmarshal([]byte(fmt.Sprintf("encryptionPublicKey: |\n  %s\n  %s\n", authorized, authorized)), &multiple)
	require.ErrorContains(t, err, "exactly one SSH public key")

	var invalid Auditlog
	err = yaml.Unmarshal([]byte("encryptionPublicKey: not-a-key\n"), &invalid)
	require.ErrorContains(t, err, "illegal public keys format")

	publicKeyFile := filepath.Join(t.TempDir(), "audit-encryption.pub")
	require.NoError(t, os.WriteFile(publicKeyFile, []byte(authorized+"\n"), 0600))
	var fromFile Auditlog
	require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf("encryptionPublicKeyFile: %s\n", publicKeyFile)), &fromFile))
	require.Equal(t, crypto.PublicKeysFile(publicKeyFile), fromFile.EncryptionPublicKeyFile)
	require.NoError(t, os.WriteFile(publicKeyFile, []byte(authorized+"\n"+authorized+"\n"), 0600))
	var multipleFromFile Auditlog
	require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf("encryptionPublicKeyFile: %s\n", publicKeyFile)), &multipleFromFile))
	require.NoError(t, os.WriteFile(publicKeyFile, []byte(authorized+"\n"), 0600))

	var combined Auditlog
	err = yaml.Unmarshal([]byte(fmt.Sprintf("encryptionPublicKey: %s\nencryptionPublicKeyFile: %s\n", authorized, publicKeyFile)), &combined)
	require.ErrorContains(t, err, "cannot be combined")

	var missing Auditlog
	require.NoError(t, yaml.Unmarshal([]byte("encryptionPublicKeyFile: missing.pub\n"), &missing))
}

func TestConfigurationValidatesFlowAuditlogReferences(t *testing.T) {
	conf := Configuration{
		Auditlogs: Auditlogs{{Name: DefaultAuditlogName}},
		Flows:     Flows{{Name: "first", Auditlog: DefaultAuditlogName}},
	}
	require.NoError(t, conf.validateAuditlogReferences())

	conf.Flows[0].Auditlog = "missing"
	require.ErrorContains(t, conf.validateAuditlogReferences(), `[flows][0][auditlog] references unknown auditlog "missing"`)
}
