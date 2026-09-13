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
				Name:         DefaultAuditlogName,
				Enabled:      DefaultAuditlogEnabled,
				IdentityFile: DefaultAuditlogIdentityFile,
				Journal: AuditlogJournal{
					Directory:        DefaultAuditlogJournalDirectory,
					MinimumFreeBytes: DefaultAuditlogJournalMinimumFreeBytes,
				},
			},
		},
		unmarshalYamlTestCase[Auditlog]{
			name: "enabled-and-customized",
			yaml: `
enabled: true
name: security
identityFile: "  custom-audit-key  "
journal:
  directory: "  custom-journal  "`,
			expected: Auditlog{
				Name:         "security",
				Enabled:      true,
				IdentityFile: "custom-audit-key",
				Journal: AuditlogJournal{
					Directory:        "custom-journal",
					MinimumFreeBytes: DefaultAuditlogJournalMinimumFreeBytes,
				},
			},
		},
		unmarshalYamlTestCase[Auditlog]{
			name:          "missing-identity-file",
			yaml:          `identityFile: " "`,
			expectedError: `[identityFile] required but absent`,
		},
		unmarshalYamlTestCase[Auditlog]{
			name: "missing-journal-directory",
			yaml: `
journal:
  directory: " "`,
			expectedError: `[directory] required but absent`,
		},
		unmarshalYamlTestCase[Auditlog]{
			name:          "unknown-field",
			yaml:          `unknown: true`,
			expectedError: `field unknown not found`,
		},
		unmarshalYamlTestCase[Auditlog]{
			name: "unknown-journal-field",
			yaml: `
journal:
  unknown: true`,
			expectedError: `field unknown not found`,
		},
	)
}

func TestAuditlogsDefaultAndExplicitEntries(t *testing.T) {
	var absent Auditlogs
	require.NoError(t, absent.SetDefaults())
	require.Equal(t, Auditlogs{{
		Name:         DefaultAuditlogName,
		Enabled:      false,
		IdentityFile: DefaultAuditlogIdentityFile,
		Journal: AuditlogJournal{
			Directory:        DefaultAuditlogJournalDirectory,
			MinimumFreeBytes: DefaultAuditlogJournalMinimumFreeBytes,
		},
	}}, absent)

	var empty Auditlogs
	require.NoError(t, yaml.Unmarshal([]byte(`[]`), &empty))
	require.Equal(t, absent, empty)

	var configured Auditlogs
	require.NoError(t, yaml.Unmarshal([]byte(`
- name: default
- name: security
  enabled: true
  identityFile: security-key
  journal:
    directory: security-journal
`), &configured))
	require.Len(t, configured, 2)
	require.Equal(t, AuditlogName("security"), configured[1].Name)
	require.True(t, configured[1].Enabled)
}

func TestAuditlogJournalMinimumFreeBytes(t *testing.T) {
	var configured AuditlogJournal
	require.NoError(t, yaml.Unmarshal([]byte("directory: journal\nminimumFreeBytes: 1048576"), &configured))
	require.Equal(t, uint64(1048576), configured.MinimumFreeBytes)
	require.True(t, configured.IsEqualTo(AuditlogJournal{Directory: "journal", MinimumFreeBytes: 1048576}))

	var unknown AuditlogJournal
	require.ErrorContains(t, yaml.Unmarshal([]byte("unknown: true"), &unknown), "field unknown not found")
}

func TestAuditlogsRejectConflicts(t *testing.T) {
	duplicateNames := Auditlogs{{Name: "duplicate"}, {Name: "duplicate"}}
	require.ErrorContains(t, duplicateNames.Validate(), "duplicates")

	duplicatePaths := Auditlogs{
		{Name: "first", Enabled: true, IdentityFile: "key", Journal: AuditlogJournal{Directory: "journal-1"}},
		{Name: "second", Enabled: true, IdentityFile: "key", Journal: AuditlogJournal{Directory: "journal-2"}},
	}
	require.ErrorContains(t, duplicatePaths.Validate(), "identityFile")

	overlappingJournals := Auditlogs{
		{Name: "first", Enabled: true, IdentityFile: "key-1", Journal: AuditlogJournal{Directory: "journals"}},
		{Name: "second", Enabled: true, IdentityFile: "key-2", Journal: AuditlogJournal{Directory: "journals/second"}},
	}
	require.ErrorContains(t, overlappingJournals.Validate(), "overlaps")

	identityInsideJournal := Auditlogs{
		{Name: "first", Enabled: true, IdentityFile: "journals/first-key", Journal: AuditlogJournal{Directory: "journal-1"}},
		{Name: "second", Enabled: true, IdentityFile: "key-2", Journal: AuditlogJournal{Directory: "journals"}},
	}
	require.ErrorContains(t, identityInsideJournal.Validate(), "is located inside")

	journalBelowIdentity := Auditlogs{{
		Name:         "first",
		Enabled:      true,
		IdentityFile: "key",
		Journal:      AuditlogJournal{Directory: "key/journal"},
	}}
	require.ErrorContains(t, journalBelowIdentity.Validate(), "is located below")

	overlappingIdentities := Auditlogs{
		{Name: "first", Enabled: true, IdentityFile: "keys", Journal: AuditlogJournal{Directory: "journal-1"}},
		{Name: "second", Enabled: true, IdentityFile: "keys/second", Journal: AuditlogJournal{Directory: "journal-2"}},
	}
	require.ErrorContains(t, overlappingIdentities.Validate(), "identityFile] overlaps")
}

func TestAuditlogNameValidationAlsoAppliesProgrammatically(t *testing.T) {
	auditlogs := Auditlogs{{
		Name:         "invalid/name",
		IdentityFile: "key",
		Journal:      AuditlogJournal{Directory: "journal"},
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
	require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf("enabled: true\nencryptionPublicKey: %s\n", authorized)), &configured))
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
	require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf("enabled: true\nencryptionPublicKeyFile: %s\n", publicKeyFile)), &fromFile))
	require.Equal(t, crypto.PublicKeysFile(publicKeyFile), fromFile.EncryptionPublicKeyFile)
	require.NoError(t, os.WriteFile(publicKeyFile, []byte(authorized+"\n"+authorized+"\n"), 0600))
	var multipleFromFile Auditlog
	require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf("enabled: true\nencryptionPublicKeyFile: %s\n", publicKeyFile)), &multipleFromFile))
	require.NoError(t, os.WriteFile(publicKeyFile, []byte(authorized+"\n"), 0600))

	var combined Auditlog
	err = yaml.Unmarshal([]byte(fmt.Sprintf("enabled: true\nencryptionPublicKey: %s\nencryptionPublicKeyFile: %s\n", authorized, publicKeyFile)), &combined)
	require.ErrorContains(t, err, "cannot be combined")

	var missingEnabled Auditlog
	require.NoError(t, yaml.Unmarshal([]byte("enabled: true\nencryptionPublicKeyFile: missing.pub\n"), &missingEnabled))
	var missingDisabled Auditlog
	require.NoError(t, yaml.Unmarshal([]byte("encryptionPublicKeyFile: missing.pub\n"), &missingDisabled))
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
