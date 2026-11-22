package environment

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestPolicyRegressionProductionSessionTargetEncoding(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context(), principal: "alice"}
	t.Run("SSH", func(t *testing.T) {
		conf := &configuration.EnvironmentSsh{}
		require.NoError(t, conf.SetDefaults())
		conf.Address, conf.User = template.MustNewString("WORK.EXAMPLE."), template.MustNewString(" {{ .authentication.principal }} ")
		conf.PortForwardingAllowed, conf.ReversePortForwardingAllowed = template.BoolOf(false), template.BoolOf(true)
		conf.IdentityFiles = template.MustNewStrings(`{{ fail "must-not-read-identity" }}`)
		conf.LoginAllowed = template.MustNewBool(`{{ fail "separate-policy-stage" }}`)
		actual, err := (&SshRepository{conf: conf}).ResolveSessionTarget(ctx)
		require.NoError(t, err)
		expected, err := session.NewTarget("ssh", map[string]string{
			"resolver": "environment-v1", "address": "work.example.:22", "user": "alice",
			"portForwardingAllowed": "false", "reversePortForwardingAllowed": "true",
		})
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})
	t.Run("Docker", func(t *testing.T) {
		conf := &configuration.EnvironmentDocker{}
		require.NoError(t, conf.SetDefaults())
		conf.Image, conf.User, conf.Directory = template.MustNewString("image"), template.MustNewString("alice"), template.MustNewString("/workspace")
		conf.Networks, conf.Volumes = template.MustNewStrings("second", "first"), template.MustNewStrings("/fixture:/data:ro")
		conf.Mounts, conf.Capabilities = template.MustNewStrings("type=bind,src=/fixture,dst=/data"), template.MustNewStrings("NET_RAW")
		conf.DnsServers, conf.DnsSearch = template.MustNewStrings("192.0.2.53"), template.MustNewStrings("example.invalid")
		conf.Privileged, conf.PortForwardingAllowed = template.BoolOf(true), template.BoolOf(false)
		conf.ShellCommand, conf.ExecCommand, conf.SftpCommand = template.MustNewStrings("sh", "-l"), template.MustNewStrings("exec"), template.MustNewStrings("sftp")
		conf.ImagePullCredentials = template.MustNewString(`{{ fail "must-not-read-secret" }}`)
		actual, err := (&DockerRepository{conf: conf, apiClient: targetDockerBackend{host: "unix:///fixture.sock"}, hostOs: sys.OsLinux, hostArch: sys.ArchAmd64}).ResolveSessionTarget(ctx)
		require.NoError(t, err)
		expected, err := session.NewTarget("docker", map[string]string{
			"resolver": "environment-v1", "backend": "unix:///fixture.sock", "os": "linux", "arch": sys.ArchAmd64.String(),
			"image": "image", "user": "alice", "directory": "/workspace", "networks": `["second","first"]`,
			"volumes": `["/fixture:/data:ro"]`, "mounts": `["type=bind,src=/fixture,dst=/data"]`, "capabilities": `["NET_RAW"]`,
			"dnsServers": `["192.0.2.53"]`, "dnsSearch": `["example.invalid"]`, "privileged": "true", "portForwardingAllowed": "false",
			"shellCommand": `["sh","-l"]`, "execCommand": `["exec"]`, "sftpCommand": `["sftp"]`,
		})
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})
	t.Run("Kubernetes", func(t *testing.T) {
		conf := &configuration.EnvironmentKubernetes{}
		require.NoError(t, conf.SetDefaults())
		conf.Os, conf.Arch = sys.OsLinux, sys.ArchAmd64
		conf.Name, conf.Namespace = template.MustNewString("work-{{ .session.id }}"), template.MustNewString("")
		conf.ServiceAccountName, conf.Image = template.MustNewString("service"), template.MustNewString("image")
		conf.User, conf.Group, conf.Directory = template.MustNewString("alice"), template.MustNewString("10001"), template.MustNewString("/workspace")
		conf.Capabilities, conf.DnsServers, conf.DnsSearch = template.MustNewStrings("NET_RAW"), template.MustNewStrings("192.0.2.53"), template.MustNewStrings("example.invalid")
		conf.Privileged, conf.PortForwardingAllowed = template.BoolOf(false), template.BoolOf(true)
		conf.ShellCommand, conf.ExecCommand, conf.SftpCommand = template.MustNewStrings("sh"), template.MustNewStrings("exec"), template.MustNewStrings("sftp")
		conf.ImagePullCredentials = template.MustNewString(`{{ fail "must-not-read-secret" }}`)
		actual, err := (&KubernetesRepository{conf: conf, client: targetKubernetesBackend{host: "https://fixture.invalid", namespace: "fixture"}}).ResolveSessionTarget(ctx)
		require.NoError(t, err)
		expected, err := session.NewTarget("kubernetes", map[string]string{
			"resolver": "environment-v1", "backend": "https://fixture.invalid", "os": "linux", "arch": sys.ArchAmd64.String(),
			"name": "work-candidate", "namespace": "fixture", "serviceAccountName": "service", "image": "image", "user": "alice", "group": "10001", "directory": "/workspace",
			"capabilities": `["NET_RAW"]`, "dnsServers": `["192.0.2.53"]`, "dnsSearch": `["example.invalid"]`, "privileged": "false", "portForwardingAllowed": "true",
			"shellCommand": `["sh"]`, "execCommand": `["exec"]`, "sftpCommand": `["sftp"]`,
		})
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})
}

type characterizationDockerBackend struct {
	targetDockerBackend
	calls int
}

func (this *characterizationDockerBackend) DaemonHost() string { this.calls++; return this.host }

type characterizationKubernetesBackend struct {
	targetKubernetesBackend
	configs, namespaces int
}

func (this *characterizationKubernetesBackend) RestConfig() *rest.Config {
	this.configs++
	return &rest.Config{Host: this.host}
}
func (this *characterizationKubernetesBackend) Namespace() string {
	this.namespaces++
	return this.namespace
}

// Validation and fingerprinting must use one metadata observation per resolution;
// the namespace fallback is read only when the configured namespace is empty.
func TestPolicyRegressionBackendMetadataReadCounts(t *testing.T) {
	// Independent subtests prevent a Docker assertion from masking Kubernetes.
	t.Run("Docker", func(t *testing.T) {
		conf := &configuration.EnvironmentDocker{}
		require.NoError(t, conf.SetDefaults())
		backend := &characterizationDockerBackend{targetDockerBackend: targetDockerBackend{host: "unix:///fixture.sock"}}
		actual, err := (&DockerRepository{conf: conf, apiClient: backend}).ResolveSessionTarget(targetTestContext{ctx: t.Context()})
		require.NoError(t, err)
		require.Equal(t, 1, backend.calls, "validate and hash the same metadata observation")
		projection, err := ProjectDockerTarget(targetTestContext{ctx: t.Context()}, conf, DockerTargetMetadata{Backend: "unix:///fixture.sock"})
		require.NoError(t, err)
		expected, err := projection.SessionTarget()
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})
	for _, test := range []struct {
		name, namespace string
		defaultReads    int
		fails           bool
	}{
		{"Kubernetes default namespace", "", 1, false},
		{"Kubernetes explicit namespace", "explicit", 0, false},
		{"Kubernetes failed namespace template", `{{ fail "private-secret" }}`, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := &configuration.EnvironmentKubernetes{}
			require.NoError(t, conf.SetDefaults())
			conf.Namespace = template.MustNewString(test.namespace)
			backend := &characterizationKubernetesBackend{targetKubernetesBackend: targetKubernetesBackend{host: "https://fixture.invalid", namespace: "default"}}
			actual, err := (&KubernetesRepository{conf: conf, client: backend}).ResolveSessionTarget(targetTestContext{ctx: t.Context()})
			require.Equal(t, 1, backend.configs, "validate and hash the same RestConfig observation")
			require.Equal(t, test.defaultReads, backend.namespaces)
			if test.fails {
				require.Empty(t, actual)
				require.True(t, berrors.Config.IsErr(err))
				require.NotContains(t, err.Error(), "private-secret")
				return
			}
			require.NoError(t, err)
			projection, err := ProjectKubernetesTarget(targetTestContext{ctx: t.Context()}, conf, KubernetesTargetMetadata{Backend: "https://fixture.invalid", Namespace: "default"})
			require.NoError(t, err)
			expected, err := projection.SessionTarget()
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
}

// Preserve error categories and cancellation without exposing sensitive target
// details; arbitrary provider causes are redacted rather than retained.
func TestPolicyRegressionTargetErrorsAndRedaction(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context()}
	for _, test := range []struct {
		name     string
		run      func() error
		category berrors.Type
	}{
		{"SSH template", func() error {
			conf := &configuration.EnvironmentSsh{}
			_ = conf.SetDefaults()
			conf.Address = template.MustNewString(`{{ fail "private-secret" }}`)
			_, err := (&SshRepository{conf: conf}).ResolveSessionTarget(ctx)
			return err
		}, berrors.Config},
		{"SSH address", func() error {
			conf := &configuration.EnvironmentSsh{}
			_ = conf.SetDefaults()
			conf.Address = template.MustNewString("private-secret://invalid")
			conf.User = template.MustNewString("user")
			_, err := (&SshRepository{conf: conf}).ResolveSessionTarget(ctx)
			return err
		}, berrors.System}, // Preserve the address parser's existing invalid-port category.
		{"Docker missing backend", func() error {
			_, err := (&DockerRepository{apiClient: targetDockerBackend{}}).ResolveSessionTarget(ctx)
			return err
		}, berrors.System},
		{"Kubernetes missing backend", func() error { _, err := (&KubernetesRepository{}).ResolveSessionTarget(ctx); return err }, berrors.System},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			require.Error(t, err)
			require.NotContains(t, err.Error(), "private-secret")
			typed, categorized := berrors.IsError(err)
			require.True(t, categorized)
			require.Equal(t, test.category, typed.Type)
		})
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := (&DummyRepository{}).ResolveSessionTarget(targetTestContext{ctx: canceled})
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, berrors.System.IsErr(err))
}

func TestPolicyRegressionLocalTemplateContextDataAndHostFunctions(t *testing.T) {
	t.Setenv("BIFROEST_CHARACTERIZATION_LOCAL_CONTEXT", "host")
	for _, managed := range []bool{false, true} {
		ctx := localTemplateContext{Request: localTemplateTestRequest{}, user: localTemplateTestAccount{}, managed: managed}
		value, err := template.MustNewString(`{{ .authorization.name }}/{{ .user.name }}/{{ env "BIFROEST_CHARACTERIZATION_LOCAL_CONTEXT" }}`).Render(ctx)
		require.NoError(t, err)
		require.Equal(t, "remote-user/local-user/host", value)
		got, err := template.MustNewBool(`{{ .user.managed }}`).Render(ctx)
		require.NoError(t, err)
		require.Equal(t, managed, got)
	}
}
