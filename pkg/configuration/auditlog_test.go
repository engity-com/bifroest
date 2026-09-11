package configuration

import "testing"

func TestAuditlog_UnmarshalYAML(t *testing.T) {
	runUnmarshalYamlTests(t,
		unmarshalYamlTestCase[Auditlog]{
			name: "defaults",
			yaml: `{}`,
			expected: Auditlog{
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
identityFile: "  custom-audit-key  "
journal:
  directory: "  custom-journal  "`,
			expected: Auditlog{
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
