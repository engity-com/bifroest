package environment

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

// These explicit v1 field sets were checked against the production resolvers
// before extracting projections. Changing their encoding invalidates existing
// session associations and is not part of the offline-testing refactoring.
func TestSessionTargetProjectionCompatibilityVectors(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context(), principal: "alice"}
	t.Run("ssh", func(t *testing.T) {
		conf := &configuration.EnvironmentSsh{}
		require.NoError(t, conf.SetDefaults())
		conf.Address = template.MustNewString("WORK.EXAMPLE.")
		conf.User = template.MustNewString(" {{ .authentication.principal }} ")
		conf.PortForwardingAllowed = template.BoolOf(false)
		conf.ReversePortForwardingAllowed = template.BoolOf(true)
		repo := &SshRepository{conf: conf}
		actual, err := repo.ResolveSessionTarget(ctx)
		require.NoError(t, err)
		expected, err := session.NewTarget("ssh", map[string]string{
			"resolver": "environment-v1", "address": "work.example.:22", "user": "alice",
			"portForwardingAllowed": "false", "reversePortForwardingAllowed": "true",
		})
		require.NoError(t, err)
		require.Equal(t, expected, actual)
		projection, err := ProjectSshTarget(ctx, conf)
		require.NoError(t, err)
		projectedTarget, err := projection.SessionTarget()
		require.NoError(t, err)
		require.Equal(t, expected, projectedTarget)
		requireProjectionField(t, projection, "address", "work.example.:22")
		requireProjectionField(t, projection, "user", "alice")
		requireProjectionField(t, projection, "portForwardingAllowed", false)
	})
	t.Run("docker", func(t *testing.T) {
		conf := &configuration.EnvironmentDocker{}
		require.NoError(t, conf.SetDefaults())
		conf.Image = template.MustNewString("example.invalid/diagnostics:approved")
		conf.User = template.MustNewString("{{ .authentication.principal }}")
		conf.Directory = template.MustNewString("/workspace")
		conf.Networks = template.MustNewStrings("frontend", "backend")
		conf.Volumes = template.MustNewStrings("/fixture:/data:ro")
		conf.Mounts = template.MustNewStrings("type=bind,src=/fixture,dst=/data,readonly")
		conf.Capabilities = template.MustNewStrings("NET_RAW")
		conf.DnsServers = template.MustNewStrings("192.0.2.53")
		conf.DnsSearch = template.MustNewStrings("example.invalid")
		conf.Privileged = template.BoolOf(true)
		conf.PortForwardingAllowed = template.BoolOf(false)
		conf.ShellCommand = template.MustNewStrings("/bin/sh", "-l")
		repo := &DockerRepository{conf: conf, apiClient: targetDockerBackend{host: "unix:///fixture.sock"}, hostOs: sys.OsLinux, hostArch: sys.ArchAmd64}
		actual, err := repo.ResolveSessionTarget(ctx)
		require.NoError(t, err)
		expected, err := session.NewTarget("docker", map[string]string{
			"resolver": "environment-v1", "backend": "unix:///fixture.sock", "os": "linux", "arch": sys.ArchAmd64.String(),
			"image": "example.invalid/diagnostics:approved", "user": "alice", "directory": "/workspace",
			"networks": `["frontend","backend"]`, "volumes": `["/fixture:/data:ro"]`,
			"mounts": `["type=bind,src=/fixture,dst=/data,readonly"]`, "capabilities": `["NET_RAW"]`,
			"dnsServers": `["192.0.2.53"]`, "dnsSearch": `["example.invalid"]`,
			"privileged": "true", "portForwardingAllowed": "false",
			"shellCommand": `["/bin/sh","-l"]`, "execCommand": `[]`, "sftpCommand": `[]`,
		})
		require.NoError(t, err)
		require.Equal(t, expected, actual)
		projection, err := ProjectDockerTarget(ctx, conf, DockerTargetMetadata{Backend: "unix:///fixture.sock", Os: sys.OsLinux, Arch: sys.ArchAmd64})
		require.NoError(t, err)
		projectedTarget, err := projection.SessionTarget()
		require.NoError(t, err)
		require.Equal(t, expected, projectedTarget)
		requireProjectionField(t, projection, "networks", []string{"frontend", "backend"})
		requireProjectionField(t, projection, "privileged", true)
	})
	t.Run("kubernetes", func(t *testing.T) {
		conf := &configuration.EnvironmentKubernetes{}
		require.NoError(t, conf.SetDefaults())
		conf.Name = template.MustNewString("work-{{ .session.id }}")
		conf.ServiceAccountName = template.MustNewString("diagnostics")
		conf.User = template.MustNewString("{{ .authentication.principal }}")
		conf.Group = template.MustNewString("10001")
		conf.Directory = template.MustNewString("/workspace")
		conf.DnsServers = template.MustNewStrings("192.0.2.53")
		repo := &KubernetesRepository{conf: conf, client: targetKubernetesBackend{host: "https://fixture.invalid", namespace: "fixture"}}
		actual, err := repo.ResolveSessionTarget(ctx)
		require.NoError(t, err)
		expected, err := session.NewTarget("kubernetes", map[string]string{
			"resolver": "environment-v1", "backend": "https://fixture.invalid", "os": "linux", "arch": sys.ArchAmd64.String(),
			"name": "work-candidate", "namespace": "fixture", "serviceAccountName": "diagnostics",
			"image": "alpine", "user": "alice", "group": "10001", "directory": "/workspace",
			"capabilities": `[]`, "dnsServers": `["192.0.2.53"]`, "dnsSearch": `[]`,
			"privileged": "false", "portForwardingAllowed": "true",
			"shellCommand": `[]`, "execCommand": `[]`, "sftpCommand": `[]`,
		})
		require.NoError(t, err)
		require.Equal(t, expected, actual)
		projection, err := ProjectKubernetesTarget(ctx, conf, KubernetesTargetMetadata{Backend: "https://fixture.invalid", Namespace: "fixture"})
		require.NoError(t, err)
		projectedTarget, err := projection.SessionTarget()
		require.NoError(t, err)
		require.Equal(t, expected, projectedTarget)
		requireProjectionField(t, projection, "namespace", "fixture")
		requireProjectionField(t, projection, "dnsServers", []string{"192.0.2.53"})
	})
}

func requireProjectionField(t *testing.T, projection TargetProjection, name string, expected any) {
	t.Helper()
	actual, present := projection.Field(name)
	require.True(t, present, "field %s must be present", name)
	require.Equal(t, expected, actual)
}

func TestTargetProjectionsDoNotInitializeRuntimeDependencies(t *testing.T) {
	// The context implements only template inputs. Accessing its inherited
	// connection/authorization methods would panic, as would any runtime client.
	ctx := targetTestContext{ctx: t.Context(), principal: "alice"}
	t.Run("ssh", func(t *testing.T) {
		conf := &configuration.EnvironmentSsh{}
		require.NoError(t, conf.SetDefaults())
		conf.Address = template.MustNewString("work.example")
		conf.User = template.MustNewString("{{ .authentication.principal }}")
		conf.KnownHostsFile = "/fixture/must-not-read-known-hosts"
		conf.IdentityFiles = template.MustNewStrings(`{{ fail "must-not-resolve-identity-files" }}`)
		conf.ConnectTimeout = template.MustNewDuration(`{{ fail "must-not-evaluate-runtime-timeout" }}`)
		conf.LoginAllowed = template.MustNewBool(`{{ fail "login-is-a-separate-policy-stage" }}`)
		conf.Banner = template.MustNewString(`{{ fail "must-not-render-banner" }}`)
		projection, err := ProjectSshTarget(ctx, conf)
		require.NoError(t, err)
		require.Equal(t, "ssh", projection.Kind())
		requireProjectionField(t, projection, "user", "alice")
		for _, name := range []string{"connectTimeout", "identityFiles", "loginAllowed", "banner", "resolver"} {
			_, present := projection.Field(name)
			require.False(t, present, "%s is not a projected target field", name)
		}
	})
	t.Run("docker", func(t *testing.T) {
		conf := &configuration.EnvironmentDocker{}
		require.NoError(t, conf.SetDefaults())
		conf.Host = template.MustNewString(`{{ fail "must-not-discover-docker" }}`)
		conf.CertPath = template.MustNewString(`{{ fail "must-not-read-docker-certificates" }}`)
		conf.ImagePullCredentials = template.MustNewString(`{{ fail "must-not-read-pull-credentials" }}`)
		conf.LoginAllowed = template.MustNewBool(`{{ fail "login-is-a-separate-policy-stage" }}`)
		projection, err := ProjectDockerTarget(ctx, conf, DockerTargetMetadata{Backend: "unix:///fixture.sock", Os: sys.OsLinux, Arch: sys.ArchAmd64})
		require.NoError(t, err)
		require.Equal(t, "docker", projection.Kind())
		requireProjectionField(t, projection, "image", "alpine")
		requireProjectionField(t, projection, "user", "") // Image metadata is not invented.
	})
	t.Run("kubernetes", func(t *testing.T) {
		conf := &configuration.EnvironmentKubernetes{}
		require.NoError(t, conf.SetDefaults())
		conf.Context = template.MustNewString(`{{ fail "must-not-select-kubeconfig-context" }}`)
		conf.ImagePullCredentials = template.MustNewString(`{{ fail "must-not-read-pull-credentials" }}`)
		conf.ImagePullSecretName = template.MustNewString(`{{ fail "must-not-resolve-pull-secret" }}`)
		conf.LoginAllowed = template.MustNewBool(`{{ fail "login-is-a-separate-policy-stage" }}`)
		projection, err := ProjectKubernetesTarget(ctx, conf, KubernetesTargetMetadata{Backend: "https://fixture.invalid", Namespace: "fixture"})
		require.NoError(t, err)
		require.Equal(t, "kubernetes", projection.Kind())
		requireProjectionField(t, projection, "namespace", "fixture")
		requireProjectionField(t, projection, "user", "")
	})
}

type projectionCountingContext struct {
	targetTestContext
	calls int
}

func (this *projectionCountingContext) GetField(name string) (any, bool, error) {
	if name == "counted" {
		this.calls++
		return "example.invalid/diagnostics:approved", true, nil
	}
	return this.targetTestContext.GetField(name)
}

func TestTargetProjectionIsAnImmutableSingleEvaluationSnapshot(t *testing.T) {
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &projectionCountingContext{targetTestContext: targetTestContext{ctx: base}}
	conf := &configuration.EnvironmentDocker{}
	require.NoError(t, conf.SetDefaults())
	conf.Image = template.MustNewString("{{ .counted }}")
	conf.Networks = template.MustNewStrings("first", "second")
	conf.PortForwardingAllowed = template.BoolOf(false)
	metadata := DockerTargetMetadata{Backend: "unix:///fixture.sock", Os: sys.OsLinux, Arch: sys.ArchAmd64}
	projection, err := ProjectDockerTarget(ctx, conf, metadata)
	require.NoError(t, err)
	target, err := projection.SessionTarget()
	require.NoError(t, err)
	require.Equal(t, 1, ctx.calls)

	list, present := projection.Field("networks")
	require.True(t, present)
	list.([]string)[0] = "caller-mutation"
	conf.Networks[0] = template.MustNewString("configuration-mutation")
	conf.Image = template.MustNewString("other-image")
	for range 3 {
		requireProjectionField(t, projection, "networks", []string{"first", "second"})
		requireProjectionField(t, projection, "image", "example.invalid/diagnostics:approved")
		actual, err := projection.SessionTarget()
		require.NoError(t, err)
		require.Equal(t, target, actual)
	}
	require.Equal(t, 1, ctx.calls, "reading a projection or hashing it must not evaluate templates again")
	other, err := ProjectDockerTarget(ctx, conf, metadata)
	require.NoError(t, err)
	otherTarget, err := other.SessionTarget()
	require.NoError(t, err)
	require.NotEqual(t, target, otherTarget)

	cancel()
	for range 4 {
		t.Run("independent reader", func(t *testing.T) {
			t.Parallel()
			for range 10 {
				list, present := projection.Field("networks")
				require.True(t, present)
				list.([]string)[0] = "reader-mutation"
				requireProjectionField(t, projection, "networks", []string{"first", "second"})
				actual, err := projection.SessionTarget()
				require.NoError(t, err, "reading the snapshot must not depend on its original context")
				require.Equal(t, target, actual)
			}
		})
	}
}

func TestTargetProjectionStopsAfterTheFirstFieldError(t *testing.T) {
	for _, test := range []struct {
		name    string
		field   string
		project func(*testing.T, Context) (TargetProjection, error)
	}{
		{"string", "address", func(t *testing.T, ctx Context) (TargetProjection, error) {
			conf := &configuration.EnvironmentSsh{}
			require.NoError(t, conf.SetDefaults())
			conf.Address = template.MustNewString(`{{ fail "sensitive-do-not-log" }}`)
			conf.User = template.MustNewString("{{ .counted }}")
			return ProjectSshTarget(ctx, conf)
		}},
		{"list", "networks", func(t *testing.T, ctx Context) (TargetProjection, error) {
			conf := &configuration.EnvironmentDocker{}
			require.NoError(t, conf.SetDefaults())
			conf.Networks = template.MustNewStrings("first", `{{ fail "sensitive-do-not-log" }}`, "{{ .counted }}")
			conf.Volumes = template.MustNewStrings("{{ .counted }}")
			return ProjectDockerTarget(ctx, conf, DockerTargetMetadata{Backend: "unix:///fixture.sock"})
		}},
		{"boolean", "privileged", func(t *testing.T, ctx Context) (TargetProjection, error) {
			conf := &configuration.EnvironmentKubernetes{}
			require.NoError(t, conf.SetDefaults())
			conf.Privileged = template.MustNewBool(`{{ fail "sensitive-do-not-log" }}`)
			conf.PortForwardingAllowed = template.MustNewBool("{{ .counted }}")
			conf.ShellCommand = template.MustNewStrings("{{ .counted }}")
			return ProjectKubernetesTarget(ctx, conf, KubernetesTargetMetadata{Backend: "https://fixture.invalid", Namespace: "fixture"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := &projectionCountingContext{targetTestContext: targetTestContext{ctx: t.Context()}}
			projection, err := test.project(t, ctx)
			require.EqualError(t, err, "cannot resolve session target field "+test.field)
			require.Equal(t, 0, ctx.calls, "no later fields may be evaluated after an error")
			require.Equal(t, TargetProjection{}, projection)
		})
	}
}

func TestTargetProjectionPreservesTypesAndDoesNotExposeInternalFields(t *testing.T) {
	conf := &configuration.EnvironmentDocker{}
	require.NoError(t, conf.SetDefaults())
	conf.PortForwardingAllowed = template.BoolOf(false)
	projection, err := ProjectDockerTarget(targetTestContext{ctx: t.Context()}, conf, DockerTargetMetadata{Backend: "unix:///fixture.sock"})
	require.NoError(t, err)
	requireProjectionField(t, projection, "user", "")
	requireProjectionField(t, projection, "portForwardingAllowed", false)
	requireProjectionField(t, projection, "volumes", []string{})
	for _, name := range []string{"missing", "resolver", "imagePullCredentials"} {
		value, present := projection.Field(name)
		require.False(t, present)
		require.Nil(t, value)
	}
	raw, err := json.Marshal(projection) //nolint:staticcheck // SA9005: deliberately verify that projections do not implicitly serialize policy values.
	require.NoError(t, err)
	require.Equal(t, "{}", string(raw), "internal projections must not become an implicit report/context dump")
	_, err = (TargetProjection{}).SessionTarget()
	require.Error(t, err)
	require.True(t, berrors.System.IsErr(err))
}

func TestTargetProjectionsRejectMissingDependenciesAndSanitizeErrors(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context()}
	docker := &configuration.EnvironmentDocker{}
	require.NoError(t, docker.SetDefaults())
	kubernetes := &configuration.EnvironmentKubernetes{}
	require.NoError(t, kubernetes.SetDefaults())
	ssh := &configuration.EnvironmentSsh{}
	require.NoError(t, ssh.SetDefaults())
	ssh.Address = template.MustNewString("work.example")
	ssh.User = template.MustNewString("account")
	metadata := DockerTargetMetadata{Backend: "unix:///fixture.sock", Os: sys.OsLinux, Arch: sys.ArchAmd64}
	for _, test := range []struct {
		name     string
		project  func() (TargetProjection, error)
		category berrors.Type
	}{
		{"missing SSH configuration", func() (TargetProjection, error) { return ProjectSshTarget(ctx, nil) }, berrors.Config},
		{"missing Docker configuration", func() (TargetProjection, error) { return ProjectDockerTarget(ctx, nil, metadata) }, berrors.Config},
		{"missing Docker backend", func() (TargetProjection, error) { return ProjectDockerTarget(ctx, docker, DockerTargetMetadata{}) }, berrors.System},
		{"missing Kubernetes configuration", func() (TargetProjection, error) {
			return ProjectKubernetesTarget(ctx, nil, KubernetesTargetMetadata{Backend: "https://fixture.invalid"})
		}, berrors.Config},
		{"missing Kubernetes backend", func() (TargetProjection, error) {
			return ProjectKubernetesTarget(ctx, kubernetes, KubernetesTargetMetadata{})
		}, berrors.System},
		{"template failure", func() (TargetProjection, error) {
			copyOfConf := *docker
			copyOfConf.Image = template.MustNewString(`{{ fail "sensitive-do-not-log" }}`)
			return ProjectDockerTarget(ctx, &copyOfConf, metadata)
		}, berrors.Config},
		{"invalid target address", func() (TargetProjection, error) {
			copyOfConf := *ssh
			copyOfConf.Address = template.MustNewString("sensitive-do-not-log://invalid")
			return ProjectSshTarget(ctx, &copyOfConf)
		}, berrors.System}, // Preserve the existing address parser's invalid-port category.
		{"oversized target field", func() (TargetProjection, error) {
			copyOfConf := *docker
			copyOfConf.Image = template.MustNewString(strings.Repeat("sensitive-do-not-log", 1000))
			return ProjectDockerTarget(ctx, &copyOfConf, metadata)
		}, berrors.Config},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection, err := test.project()
			require.Error(t, err)
			require.True(t, test.category.IsErr(err), "%v", err)
			require.NotContains(t, err.Error(), "sensitive-do-not-log")
			require.Equal(t, TargetProjection{}, projection, "a failed projection must not expose a partial target")
		})
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, project := range []func(Context) (TargetProjection, error){
		func(ctx Context) (TargetProjection, error) { return ProjectSshTarget(ctx, ssh) },
		func(ctx Context) (TargetProjection, error) { return ProjectDockerTarget(ctx, docker, metadata) },
		func(ctx Context) (TargetProjection, error) {
			return ProjectKubernetesTarget(ctx, kubernetes, KubernetesTargetMetadata{Backend: "https://fixture.invalid", Namespace: "fixture"})
		},
	} {
		projection, err := project(targetTestContext{ctx: canceled})
		require.ErrorIs(t, err, context.Canceled)
		require.True(t, berrors.System.IsErr(err))
		require.Equal(t, TargetProjection{}, projection)
	}
}

type projectionNamespaceBackend struct {
	targetKubernetesBackend
	resolveNamespace func() string
}

func (this projectionNamespaceBackend) Namespace() string { return this.resolveNamespace() }

func TestKubernetesTargetProjectionPreservesLazyNamespaceResolution(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context()}
	conf := &configuration.EnvironmentKubernetes{}
	require.NoError(t, conf.SetDefaults())
	conf.Namespace = template.MustNewString("explicit")
	repo := &KubernetesRepository{conf: conf, client: projectionNamespaceBackend{
		targetKubernetesBackend: targetKubernetesBackend{host: "https://fixture.invalid"},
		resolveNamespace: func() string {
			panic("an explicit namespace must not request backend defaults")
		},
	}}
	_, err := repo.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	projection, err := ProjectKubernetesTarget(ctx, conf, KubernetesTargetMetadata{Backend: "https://fixture.invalid", Namespace: "unused"})
	require.NoError(t, err)
	requireProjectionField(t, projection, "namespace", "explicit")

	conf.Namespace = template.MustNewString(`{{ fail "namespace-not-available" }}`)
	_, err = repo.ResolveSessionTarget(ctx)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "namespace-not-available")

	conf.Namespace = template.MustNewString("")
	calls := 0
	repo.client = projectionNamespaceBackend{
		targetKubernetesBackend: targetKubernetesBackend{host: "https://fixture.invalid"},
		resolveNamespace:        func() string { calls++; return "backend-default" },
	}
	actual, err := repo.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	projection, err = ProjectKubernetesTarget(ctx, conf, KubernetesTargetMetadata{Backend: "https://fixture.invalid", Namespace: "backend-default"})
	require.NoError(t, err)
	projectedTarget, err := projection.SessionTarget()
	require.NoError(t, err)
	require.Equal(t, actual, projectedTarget)
}
