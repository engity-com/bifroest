package configuration_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	_ "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuditlogTargetSftpPasswordRoundtrip(t *testing.T) {
	raw := `name: archive
type: sftp
address: archive.example.org
user: audit
directory: /srv/bifroest/audit
knownHosts: archive.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEokQdxJkk6AUaFTmkdh6cHfdmR7Q5F7bM2vCeVx1z9i
password: '{{ env ` + "`SFTP_PASSWORD`" + ` }}'
connectTimeout: 5s
`
	var actual configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal([]byte(raw), &actual))
	value, ok := actual.V.(*configuration.AuditlogTargetSftp)
	require.True(t, ok)
	require.Equal(t, "archive.example.org:22", value.Address)
	connectTimeout, err := value.ConnectTimeout.Render(nil)
	require.NoError(t, err)
	require.Equal(t, 5*time.Second, connectTimeout)
	require.Equal(t, []string{"sftp"}, value.FeatureFlags())

	encoded, err := yaml.Marshal(actual)
	require.NoError(t, err)
	var roundtrip configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal(encoded, &roundtrip))
	require.True(t, actual.IsEqualTo(roundtrip))
}

func TestAuditlogTargetSftpKeyConfiguration(t *testing.T) {
	var actual configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal([]byte(`name: archive
type: SFTP
address: '[2001:db8::1]:2222'
user: audit
directory: /archive
acceptAllHostKeys: true
identityFiles:
  - /run/secrets/archive-key
`), &actual))
	value := actual.V.(*configuration.AuditlogTargetSftp)
	require.Equal(t, "[2001:db8::1]:2222", value.Address)
	require.Equal(t, []string{"/run/secrets/archive-key"}, value.IdentityFiles)
	connectTimeout, err := value.ConnectTimeout.Render(nil)
	require.NoError(t, err)
	require.Equal(t, 10*time.Second, connectTimeout)
}

func TestAuditlogTargetSftpExplicitZeroTimeoutRoundtrip(t *testing.T) {
	var actual configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal([]byte(`name: archive
type: sftp
address: archive.example.org
user: audit
directory: /archive
acceptAllHostKeys: true
password: secret
connectTimeout: 0s
`), &actual))
	encoded, err := yaml.Marshal(actual)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "connectTimeout: 0s")
	var roundtrip configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal(encoded, &roundtrip))
	require.True(t, actual.IsEqualTo(roundtrip))
}

func TestAuditlogTargetSftpRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		err  string
	}{
		{"unknown-field", "extra: true", "field extra not found"},
		{"address", "address: bad,host", "unsafe characters"},
		{"user", "user: ''", "[user] required"},
		{"relative-directory", "directory: archive", "absolute POSIX"},
		{"traversal", "directory: /archive/../other", "relative path component"},
		{"missing-trust", "", "knownHosts"},
		{"invalid-known-hosts", "knownHosts: invalid\npassword: secret", "[knownHosts] illegal"},
		{"mixed-trust", "knownHosts: host ssh-ed25519 bad\nacceptAllHostKeys: true", "cannot be combined"},
		{"missing-auth", "acceptAllHostKeys: true", "identityFiles"},
		{"mixed-auth", "acceptAllHostKeys: true\nidentityFiles: [key]\npassword: secret", "cannot be combined"},
		{"duplicate-key", "acceptAllHostKeys: true\nidentityFiles: [key, key]", "duplicates"},
		{"empty-timeout", "acceptAllHostKeys: true\npassword: secret\nconnectTimeout: ''", "cannot be empty"},
		{"negative-timeout", "acceptAllHostKeys: true\npassword: secret\nconnectTimeout: -1s", "cannot be negative"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := "name: archive\ntype: sftp\naddress: host\nuser: audit\ndirectory: /archive\n" + test.yaml + "\n"
			switch test.name {
			case "address":
				raw = "name: archive\ntype: sftp\naddress: bad,host\nuser: audit\ndirectory: /archive\nacceptAllHostKeys: true\npassword: secret\n"
			case "user":
				raw = "name: archive\ntype: sftp\naddress: host\nuser: ''\ndirectory: /archive\nacceptAllHostKeys: true\npassword: secret\n"
			case "relative-directory", "traversal":
				directory := "archive"
				if test.name == "traversal" {
					directory = "/archive/../other"
				}
				raw = "name: archive\ntype: sftp\naddress: host\nuser: audit\ndirectory: " + directory + "\nacceptAllHostKeys: true\npassword: secret\n"
			}
			var actual configuration.AuditlogTarget
			err := yaml.Unmarshal([]byte(raw), &actual)
			require.ErrorContains(t, err, test.err)
		})
	}
}

func TestAuditlogTargetSftpRendersCredentials(t *testing.T) {
	t.Setenv("SFTP_USER", " archive ")
	t.Setenv("SFTP_PASSWORD", "secret")
	value := configuration.AuditlogTargetSftp{
		User:           template.MustNewString("{{ env `SFTP_USER` }}"),
		Password:       template.MustNewString("{{ env `SFTP_PASSWORD` }}"),
		ConnectTimeout: template.DurationOf(time.Second),
	}
	rendered, err := value.Render(nil)
	require.NoError(t, err)
	require.Equal(t, "archive", rendered.User)
	require.Equal(t, "secret", rendered.Password)
	require.Equal(t, time.Second, rendered.ConnectTimeout)
}
