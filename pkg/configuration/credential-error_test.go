package configuration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestConfigurationCredentialDecodeErrorsAreRedacted(t *testing.T) {
	const secret = "ZXSecretMarkerNotForDiagnostics"
	for _, test := range []struct {
		name   string
		field  string
		prefix string
		create func() any
	}{
		{"simple password", "password", "name: test\n", func() any { return &AuthorizationSimpleEntry{} }},
		{"OIDC client ID", "clientId", "issuer: https://example.invalid\n", func() any { return &AuthorizationOidcDeviceAuth{} }},
		{"OIDC client secret", "clientSecret", "issuer: https://example.invalid\nclientId: test\n", func() any { return &AuthorizationOidcDeviceAuth{} }},
		{"S3 access key", "accessKeyId", "bucket: test\n", func() any { return &AuditlogTargetS3{} }},
		{"S3 secret key", "secretAccessKey", "bucket: test\n", func() any { return &AuditlogTargetS3{} }},
		{"S3 session token", "sessionToken", "bucket: test\n", func() any { return &AuditlogTargetS3{} }},
		{"SFTP user", "user", "address: example.invalid:22\n", func() any { return &AuditlogTargetSftp{} }},
		{"SFTP password", "password", "address: example.invalid:22\nuser: test\n", func() any { return &AuditlogTargetSftp{} }},
		{"WebDAV username", "username", "endpoint: https://example.invalid\n", func() any { return &AuditlogTargetWebdav{} }},
		{"WebDAV password", "password", "endpoint: https://example.invalid\nusername: test\n", func() any { return &AuditlogTargetWebdav{} }},
		{"Docker registry credentials", "imagePullCredentials", "", func() any { return &EnvironmentDocker{} }},
		{"Kubernetes registry credentials", "imagePullCredentials", "", func() any { return &EnvironmentKubernetes{} }},
		{"environment variables", "variables", "type: docker\n", func() any { return &Environment{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, value := range []string{
				"'{{ " + secret + " }}'",
				"!!bool " + secret,
				"[" + secret + "]",
				"{" + secret + ": value, " + secret + ": duplicate}",
			} {
				t.Run(value, func(t *testing.T) {
					err := yaml.Unmarshal([]byte(test.prefix+test.field+": "+value+"\n"), test.create())
					require.ErrorContains(t, err, "["+test.field+"]")
					require.ErrorContains(t, err, "***redacted***")
					require.NotContains(t, err.Error(), secret[:7], "even truncated YAML excerpts must not contain credentials")
					var location *LocationError
					require.ErrorAs(t, err, &location)
					require.Positive(t, location.Line)
					require.Positive(t, location.Column)
					var redacted *configurationCredentialError
					require.ErrorAs(t, err, &redacted)
					require.NotNil(t, errors.Unwrap(redacted), "original typed causes remain available, but are not displayed")
				})
			}
		})
	}
}

func TestConfigurationCredentialAliasesAndMergesAreRedacted(t *testing.T) {
	for _, contents := range []string{
		"name: test\nother: &credential 'AliasCredentialMarker'\npassword: *credential\n",
		"name: test\n<<: {password: 'MergeCredentialMarker'}\n",
		"name: test\nother: &credentials {password: 'MergedAliasCredentialMarker'}\n<<: *credentials\n",
		"name: test\npassword: &recursive [RecursiveCredentialMarker, *recursive]\n",
	} {
		var entry AuthorizationSimpleEntry
		err := yaml.Unmarshal([]byte(contents), &entry)
		require.ErrorContains(t, err, "[password]")
		require.ErrorContains(t, err, "***redacted***")
		require.NotContains(t, err.Error(), "CredentialMarker")
	}
}

func TestConfigurationPasswordFileErrorsAreRedacted(t *testing.T) {
	const secret = "PasswordFileCredentialMarker"
	path := filepath.Join(t.TempDir(), "password")
	require.NoError(t, os.WriteFile(path, []byte(secret), 0600))
	var entry AuthorizationSimpleEntry
	err := yaml.Unmarshal([]byte(fmt.Sprintf("name: test\npasswordFile: %q\n", filepath.ToSlash(path))), &entry)
	require.ErrorContains(t, err, "[passwordFile]")
	require.ErrorContains(t, err, "***redacted***")
	require.NotContains(t, err.Error(), secret)
	require.ErrorIs(t, err, crypto.ErrIllegalPasswordFile)
}

func TestConfigurationCredentialValidationErrorsAreRedacted(t *testing.T) {
	entry := AuthorizationSimpleEntry{Name: "test", Password: crypto.Password("ValidationCredentialMarker")}
	err := entry.Validate()
	require.ErrorContains(t, err, "[password] illegal password")
	require.NotContains(t, err.Error(), "ValidationCredentialMarker")
	require.ErrorIs(t, err, crypto.ErrIllegalPassword)
}

func TestConfigurationCredentialErrorsKeepNonSecretDiagnostics(t *testing.T) {
	var oidc AuthorizationOidcDeviceAuth
	err := yaml.Unmarshal([]byte("issuer: https://example.invalid\nclientId: test\n"), &oidc)
	require.ErrorContains(t, err, "[clientSecret] required but absent")
	var s3 AuditlogTargetS3
	err = yaml.Unmarshal([]byte("bucket: test\naccessKeyId: valid\npathStyle: notBool\n"), &s3)
	require.ErrorContains(t, err, "notBool")
	require.NotContains(t, err.Error(), "***redacted***")
	var typeError *yaml.TypeError
	require.ErrorAs(t, err, &typeError)
}

func TestConfigurationCredentialTemplatesAreNotEvaluated(t *testing.T) {
	for _, contents := range []string{
		"endpoint: https://example.invalid\nusername: test\npassword: '{{ fail `DoNotExecuteCredentialTemplate` }}'\n",
		"endpoint: https://example.invalid\nusername: test\npassword: '{{ file `does-not-exist-secret-file` }}'\n",
	} {
		var conf AuditlogTargetWebdav
		require.NoError(t, yaml.Unmarshal([]byte(contents), &conf))
		require.False(t, conf.Password.IsHardCoded())
	}
}

func TestConfigurationCredentialDecoderPreservesDefaultsAndDecodesOnce(t *testing.T) {
	var calls, secretCalls int
	target := struct {
		Password template.String             `yaml:"password" sensitive:"true"`
		Other    credentialTestDecodeCounter `yaml:"other"`
		Secret   credentialTestDecodeCounter `yaml:"secret" sensitive:"true"`
		hidden   bool
	}{Password: template.MustNewString("default credential"), Other: credentialTestDecodeCounter{calls: &calls}, Secret: credentialTestDecodeCounter{calls: &secretCalls}, hidden: true}
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("other: {}\nsecret: {}\npassword: null\n"), &node))
	require.NoError(t, decodeConfigurationFields(node.Content[0], &target))
	require.Equal(t, 1, calls)
	require.Equal(t, 1, secretCalls)
	require.True(t, target.hidden)
	require.Equal(t, "default credential", target.Password.String())
}

type credentialTestDecodeCounter struct{ calls *int }

func (this *credentialTestDecodeCounter) UnmarshalYAML(*yaml.Node) error {
	*this.calls++
	return nil
}

func TestConfigurationCredentialLoadErrorIsSafe(t *testing.T) {
	var conf Configuration
	err := conf.LoadFromYaml(strings.NewReader("flows:\n  - name: test\n    authorization:\n      type: simple\n      entries:\n        - name: test\n          password: LoaderCredentialMarker\n    environment:\n      type: dummy\n"), "secret-config.yaml")
	require.ErrorContains(t, err, "secret-config.yaml")
	require.ErrorContains(t, err, "[password]")
	require.ErrorContains(t, err, "***redacted***")
	require.NotContains(t, err.Error(), "LoaderCredentialMarker")
	require.ErrorIs(t, err, crypto.ErrIllegalPassword)
}
