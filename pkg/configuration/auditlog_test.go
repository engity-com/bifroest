package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
					Directory: DefaultAuditlogJournalDirectory,
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
					Directory: "custom-journal",
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
		Journal:      AuditlogJournal{Directory: DefaultAuditlogJournalDirectory},
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
