package configuration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	_ "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuditlogTargetS3YAML(t *testing.T) {
	var actual configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal([]byte(`
name: archive
type: S3
bucket: audit-archive
region: eu-central-1
prefix: " production/bifroest "
endpoint: " https://objects.example.invalid/ "
pathStyle: true
expectedBucketOwner: " 123456789012 "
destinationIdentity: " tenant-production "
accessKeyId: '{{ env "ARCHIVE_ACCESS_KEY_ID" }}'
secretAccessKey: '{{ env "ARCHIVE_SECRET_ACCESS_KEY" }}'
sessionToken: '{{ env "ARCHIVE_SESSION_TOKEN" }}'
publishAttemptTimeout: 15s
`), &actual))
	require.Equal(t, configuration.AuditlogTargetName("archive"), actual.Name)
	expected := configuration.AuditlogTargetS3{
		Bucket:                "audit-archive",
		Region:                template.MustNewString("eu-central-1"),
		Prefix:                "production/bifroest",
		Endpoint:              "https://objects.example.invalid",
		PathStyle:             true,
		ExpectedBucketOwner:   "123456789012",
		DestinationIdentity:   "tenant-production",
		AccessKeyId:           template.MustNewString("{{ env \"ARCHIVE_ACCESS_KEY_ID\" }}"),
		SecretAccessKey:       template.MustNewString("{{ env \"ARCHIVE_SECRET_ACCESS_KEY\" }}"),
		SessionToken:          template.MustNewString("{{ env \"ARCHIVE_SESSION_TOKEN\" }}"),
		PublishAttemptTimeout: template.DurationOf(15 * time.Second),
	}
	require.True(t, expected.IsEqualTo(actual.V))

	encoded, err := yaml.Marshal(actual)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "type: s3")
	var roundTripped configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal(encoded, &roundTripped))
	require.True(t, actual.IsEqualTo(roundTripped))
	require.Contains(t, configuration.GetSupportedAuditlogTargetFeatureFlags(), "s3")
}

func TestAuditlogTargetS3EnvironmentDefaults(t *testing.T) {
	t.Setenv("AWS_REGION", "eu-central-1")
	t.Setenv("AWS_DEFAULT_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "modern-access")
	t.Setenv("AWS_ACCESS_KEY", "legacy-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "modern-secret")
	t.Setenv("AWS_SECRET_KEY", "legacy-secret")
	t.Setenv("AWS_SESSION_TOKEN", "session")

	var actual configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal([]byte("name: archive\ntype: s3\nbucket: audit-archive\n"), &actual))
	conf := actual.V.(*configuration.AuditlogTargetS3)
	values, err := conf.Render(nil)
	require.NoError(t, err)
	require.Equal(t, configuration.AuditlogTargetS3Values{
		Region:                "eu-central-1",
		AccessKeyId:           "modern-access",
		SecretAccessKey:       "modern-secret",
		SessionToken:          "session",
		PublishAttemptTimeout: 2 * time.Minute,
	}, values)
	encoded, err := yaml.Marshal(actual)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "sessionToken:")
	var roundTripped configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal(encoded, &roundTripped))
	require.True(t, actual.IsEqualTo(roundTripped))

	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	values, err = conf.Render(nil)
	require.NoError(t, err)
	require.Equal(t, "us-east-1", values.Region)
	require.Equal(t, "legacy-access", values.AccessKeyId)
	require.Equal(t, "legacy-secret", values.SecretAccessKey)

	conf.AccessKeyId = template.MustNewString("target-access")
	conf.SecretAccessKey = template.MustNewString("target-secret")
	values, err = conf.Render(nil)
	require.NoError(t, err)
	require.Empty(t, values.SessionToken)
}

func TestAuditlogTargetS3PreservesExplicitSessionToken(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "default-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "default-secret")
	t.Setenv("AWS_SESSION_TOKEN", "environment-token")
	tests := []struct {
		name         string
		credentials  string
		sessionToken string
		expected     string
		serialized   bool
	}{
		{"empty-with-default-credentials", "", "''", "", true},
		{"AWS-template-with-custom-credentials", "accessKeyId: custom-access\nsecretAccessKey: custom-secret\n", "'{{ env `AWS_SESSION_TOKEN` }}'", "environment-token", true},
		{"null-with-custom-credentials", "accessKeyId: custom-access\nsecretAccessKey: custom-secret\n", "null", "", false},
		{"null-alias-with-custom-credentials", "prefix: &nothing null\naccessKeyId: custom-access\nsecretAccessKey: custom-secret\n", "*nothing", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var actual configuration.AuditlogTarget
			raw := "name: archive\ntype: s3\nbucket: audit-archive\nregion: eu-central-1\n" +
				test.credentials + "sessionToken: " + test.sessionToken + "\n"
			require.NoError(t, yaml.Unmarshal([]byte(raw), &actual))
			values, err := actual.V.(*configuration.AuditlogTargetS3).Render(nil)
			require.NoError(t, err)
			require.Equal(t, test.expected, values.SessionToken)

			encoded, err := yaml.Marshal(actual)
			require.NoError(t, err)
			if test.serialized {
				require.Contains(t, string(encoded), "sessionToken:")
			} else {
				require.NotContains(t, string(encoded), "sessionToken:")
			}
			var roundTripped configuration.AuditlogTarget
			require.NoError(t, yaml.Unmarshal(encoded, &roundTripped))
			require.True(t, actual.IsEqualTo(roundTripped))
			values, err = roundTripped.V.(*configuration.AuditlogTargetS3).Render(nil)
			require.NoError(t, err)
			require.Equal(t, test.expected, values.SessionToken)
		})
	}
}

func TestAuditlogTargetS3EqualityIncludesCredentialTemplates(t *testing.T) {
	base := configuration.AuditlogTargetS3{
		Bucket:          "audit-archive",
		Region:          template.MustNewString("eu-central-1"),
		AccessKeyId:     template.MustNewString("access"),
		SecretAccessKey: template.MustNewString("secret"),
		SessionToken:    template.MustNewString("token"),
	}
	tests := []struct {
		name   string
		change func(*configuration.AuditlogTargetS3)
	}{
		{"region", func(value *configuration.AuditlogTargetS3) { value.Region = template.MustNewString("us-east-1") }},
		{"access-key", func(value *configuration.AuditlogTargetS3) {
			value.AccessKeyId = template.MustNewString("other-access")
		}},
		{"secret-key", func(value *configuration.AuditlogTargetS3) {
			value.SecretAccessKey = template.MustNewString("other-secret")
		}},
		{"session-token", func(value *configuration.AuditlogTargetS3) {
			value.SessionToken = template.MustNewString("other-token")
		}},
		{"destination-identity", func(value *configuration.AuditlogTargetS3) { value.DestinationIdentity = "other-tenant" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.change(&changed)
			require.False(t, base.IsEqualTo(changed))
		})
	}
}

func TestAuditlogTargetS3RendersCredentialFile(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret-access-key")
	require.NoError(t, os.WriteFile(secretFile, []byte("file-secret"), 0o600))
	conf := configuration.AuditlogTargetS3{
		Region:          template.MustNewString("eu-central-1"),
		AccessKeyId:     template.MustNewString("access"),
		SecretAccessKey: template.MustNewString("{{ file `" + secretFile + "` }}"),
	}

	values, err := conf.Render(nil)
	require.NoError(t, err)
	require.Equal(t, "file-secret", values.SecretAccessKey)
}

func TestAuditlogTargetS3RenderRejectsInvalidValues(t *testing.T) {
	t.Setenv("MISSING_S3_VALUE", "")
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{"missing-region", "region: '{{ env `MISSING_S3_VALUE` }}'\naccessKeyId: access\nsecretAccessKey: secret", "[region] required"},
		{"invalid-region", "region: '{{ env `INVALID_S3_REGION` }}'\naccessKeyId: access\nsecretAccessKey: secret", "illegal character"},
		{"missing-access-key", "region: eu-central-1\naccessKeyId: '{{ env `MISSING_S3_VALUE` }}'\nsecretAccessKey: secret", "[accessKeyId] required"},
		{"missing-secret-key", "region: eu-central-1\naccessKeyId: access\nsecretAccessKey: '{{ env `MISSING_S3_VALUE` }}'", "[secretAccessKey] required"},
		{"render-failure", "region: eu-central-1\naccessKeyId: '{{ fail \"cannot-load\" }}'\nsecretAccessKey: secret", "[accessKeyId] cannot render"},
	}
	t.Setenv("INVALID_S3_REGION", "eu_central_1")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var actual configuration.AuditlogTarget
			require.NoError(t, yaml.Unmarshal([]byte("name: archive\ntype: s3\nbucket: audit-archive\n"+test.body+"\n"), &actual))
			_, err := actual.V.(*configuration.AuditlogTargetS3).Render(nil)
			require.ErrorContains(t, err, test.expected)
		})
	}
}

func TestAuditlogTargetS3RejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{"missing-bucket", "region: eu-central-1", "[bucket]"},
		{"short-bucket", "bucket: ab\nregion: eu-central-1", "between 3 and 63"},
		{"uppercase-bucket", "bucket: Audit-Archive\nregion: eu-central-1", "lowercase letter or digit"},
		{"ip-bucket", "bucket: 127.0.0.1\nregion: eu-central-1", "IP address"},
		{"reserved-bucket", "bucket: archive-s3alias\nregion: eu-central-1", "reserved suffix"},
		{"express-alias-bucket", "bucket: archive--xa-s3\nregion: eu-central-1", "reserved suffix"},
		{"account-regional-bucket", "bucket: archive-an\nregion: eu-central-1", "reserved suffix"},
		{"empty-region", "bucket: audit-archive\nregion: ''", "[region] required"},
		{"invalid-region", "bucket: audit-archive\nregion: eu_central_1", "illegal character"},
		{"leading-region-hyphen", "bucket: audit-archive\nregion: -eu-central-1", "must start and end"},
		{"trailing-region-hyphen", "bucket: audit-archive\nregion: eu-central-1-", "must start and end"},
		{"long-region", "bucket: audit-archive\nregion: " + strings.Repeat("a", 64), "exceeds 63 bytes"},
		{"leading-prefix-slash", "bucket: audit-archive\nregion: eu-central-1\nprefix: /audit", "relative path component"},
		{"relative-prefix", "bucket: audit-archive\nregion: eu-central-1\nprefix: audit/../other", "relative path component"},
		{"backslash-prefix", "bucket: audit-archive\nregion: eu-central-1\nprefix: 'audit\\other'", "backslash"},
		{"long-prefix", "bucket: audit-archive\nregion: eu-central-1\nprefix: " + strings.Repeat("a", 858), "exceeds 857 bytes"},
		{"http-endpoint", "bucket: audit-archive\nregion: eu-central-1\nendpoint: http://objects.example.invalid", "absolute HTTPS"},
		{"endpoint-path", "bucket: audit-archive\nregion: eu-central-1\nendpoint: https://objects.example.invalid/base", "must not contain a path"},
		{"endpoint-user", "bucket: audit-archive\nregion: eu-central-1\nendpoint: https://user@objects.example.invalid", "user information"},
		{"endpoint-empty-host", "bucket: audit-archive\nregion: eu-central-1\nendpoint: 'https://:443'", "absolute HTTPS"},
		{"endpoint-empty-port", "bucket: audit-archive\nregion: eu-central-1\nendpoint: 'https://objects.example.invalid:'", "empty port"},
		{"endpoint-invalid-port", "bucket: audit-archive\nregion: eu-central-1\nendpoint: 'https://objects.example.invalid:65536'", "invalid port"},
		{"endpoint-invalid-host", "bucket: audit-archive\nregion: eu-central-1\nendpoint: 'https://bad_host.example'", "invalid host"},
		{"ambiguous-custom-endpoint", "bucket: audit-archive\nregion: eu-central-1\nendpoint: https://objects.example.invalid", "[destinationIdentity] or [expectedBucketOwner]"},
		{"endpoint-empty-query", "bucket: audit-archive\nregion: eu-central-1\nendpoint: 'https://objects.example.invalid?'", "query"},
		{"endpoint-empty-fragment", "bucket: audit-archive\nregion: eu-central-1\nendpoint: 'https://objects.example.invalid#'", "fragment"},
		{"invalid-owner-length", "bucket: audit-archive\nregion: eu-central-1\nexpectedBucketOwner: '123'", "exactly 12 digits"},
		{"invalid-owner-character", "bucket: audit-archive\nregion: eu-central-1\nexpectedBucketOwner: 12345678901x", "non-decimal"},
		{"long-destination-identity", "bucket: audit-archive\nregion: eu-central-1\ndestinationIdentity: " + strings.Repeat("a", 257), "exceeds 256 bytes"},
		{"control-in-destination-identity", "bucket: audit-archive\nregion: eu-central-1\ndestinationIdentity: \"tenant\\nother\"", "control character"},
		{"empty-access-key", "bucket: audit-archive\nregion: eu-central-1\naccessKeyId: ''", "[accessKeyId] required"},
		{"empty-secret-key", "bucket: audit-archive\nregion: eu-central-1\nsecretAccessKey: ''", "[secretAccessKey] required"},
		{"mixed-default-credentials", "bucket: audit-archive\nregion: eu-central-1\naccessKeyId: custom", "must either both use their defaults or both be configured"},
		{"zero-publish-timeout", "bucket: audit-archive\nregion: eu-central-1\npublishAttemptTimeout: 0s", "must be positive"},
		{"negative-publish-timeout", "bucket: audit-archive\nregion: eu-central-1\npublishAttemptTimeout: -1s", "must be positive"},
		{"unknown-field", "bucket: audit-archive\nregion: eu-central-1\nsecretKey: forbidden", "field secretKey not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var actual configuration.AuditlogTarget
			err := yaml.Unmarshal([]byte("name: archive\ntype: s3\n"+test.body+"\n"), &actual)
			require.ErrorContains(t, err, test.expected)
		})
	}
}

func TestAuditlogTargetS3AcceptsMaximumPrefix(t *testing.T) {
	var actual configuration.AuditlogTarget
	err := yaml.Unmarshal([]byte("name: archive\ntype: s3\nbucket: audit-archive\nregion: eu-central-1\nprefix: "+strings.Repeat("a", 857)+"\n"), &actual)
	require.NoError(t, err)
}

func TestAuditlogTargetS3AcceptsIPv6Endpoint(t *testing.T) {
	var actual configuration.AuditlogTarget
	err := yaml.Unmarshal([]byte("name: archive\ntype: s3\nbucket: audit-archive\nregion: eu-central-1\nendpoint: https://[2001:db8::1]:9000\npathStyle: true\ndestinationIdentity: tenant-a\n"), &actual)
	require.NoError(t, err)
}

func TestAuditlogTargetS3AcceptsUnambiguousDestinations(t *testing.T) {
	for _, body := range []string{
		"bucket: audit-archive\nregion: eu-central-1",
		"bucket: audit-archive\nregion: eu-central-1\nendpoint: https://objects.example.invalid\ndestinationIdentity: tenant-a",
		"bucket: audit-archive\nregion: eu-central-1\nendpoint: https://objects.example.invalid\nexpectedBucketOwner: '123456789012'",
	} {
		var actual configuration.AuditlogTarget
		require.NoError(t, yaml.Unmarshal([]byte("name: archive\ntype: s3\n"+body+"\n"), &actual))
	}
}

func TestAuditlogTargetS3RejectsNonCanonicalDestinationIdentity(t *testing.T) {
	conf := configuration.AuditlogTargetS3{
		Bucket:              "audit-archive",
		Region:              template.MustNewString("eu-central-1"),
		Endpoint:            "https://objects.example.invalid",
		DestinationIdentity: " tenant-a ",
		AccessKeyId:         template.MustNewString("access"),
		SecretAccessKey:     template.MustNewString("secret"),
	}
	require.ErrorContains(t, conf.Validate(), "leading or trailing whitespace")
}
