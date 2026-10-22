package environment

import (
	"context"
	"fmt"
	"testing"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	bkp "github.com/engity-com/bifroest/pkg/kubernetes"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

type targetTestBase interface{ Context }
type targetTestContext struct {
	targetTestBase
	ctx       context.Context
	principal string
}

func (this targetTestContext) Context() context.Context { return this.ctx }
func (this targetTestContext) GetField(name string) (any, bool, error) {
	switch name {
	case "authentication":
		return authentication.Identity{Principal: this.principal, Issuer: "issuer", Subject: "subject"}, true, nil
	case "session":
		return map[string]any{"id": "candidate"}, true, nil
	default:
		return nil, false, fmt.Errorf("missing target test field")
	}
}

// Only immutable backend metadata is implemented. Any attempt to provision,
// pull images, resolve credentials or call a remote API panics via nil embeds.
type targetDockerBackend struct {
	client.APIClient
	host string
}

func (this targetDockerBackend) DaemonHost() string { return this.host }

type targetKubernetesBackend struct {
	bkp.Client
	host, namespace string
}

func (this targetKubernetesBackend) RestConfig() *rest.Config { return &rest.Config{Host: this.host} }
func (this targetKubernetesBackend) Namespace() string        { return this.namespace }

func TestContainerSessionTargetsArePureAndSeparateSelectors(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context(), principal: "alice"}
	t.Run("docker", func(t *testing.T) {
		conf := &configuration.EnvironmentDocker{}
		require.NoError(t, conf.SetDefaults())
		conf.User = template.MustNewString("{{.authentication.principal}}")
		conf.ImagePullCredentials = template.MustNewString(`{{ fail "must not read pull secrets" }}`)
		repo := &DockerRepository{conf: conf, apiClient: targetDockerBackend{host: "unix:///docker.sock"}, hostOs: sys.OsLinux, hostArch: sys.ArchAmd64}
		first, err := repo.ResolveSessionTarget(ctx)
		require.NoError(t, err)
		other, err := repo.ResolveSessionTarget(targetTestContext{ctx: t.Context(), principal: "bob"})
		require.NoError(t, err)
		require.NotEqual(t, first, other)
		for _, change := range []func(*configuration.EnvironmentDocker){
			func(c *configuration.EnvironmentDocker) { c.Image = template.MustNewString("other-image") },
			func(c *configuration.EnvironmentDocker) { c.Volumes = template.MustNewStrings("/sensitive:/data") },
			func(c *configuration.EnvironmentDocker) { c.Networks = template.MustNewStrings("other-network") },
			func(c *configuration.EnvironmentDocker) { c.Privileged = template.BoolOf(true) },
			func(c *configuration.EnvironmentDocker) { c.Capabilities = template.MustNewStrings("SYS_ADMIN") },
			func(c *configuration.EnvironmentDocker) { c.Directory = template.MustNewString("/other") },
		} {
			copyOfConf := *conf
			change(&copyOfConf)
			repo.conf = &copyOfConf
			got, err := repo.ResolveSessionTarget(ctx)
			require.NoError(t, err)
			require.NotEqual(t, first, got)
		}
		repo.conf = conf
		repo.apiClient = targetDockerBackend{host: "unix:///other.sock"}
		other, err = repo.ResolveSessionTarget(ctx)
		require.NoError(t, err)
		require.NotEqual(t, first, other)
	})
	t.Run("kubernetes", func(t *testing.T) {
		conf := &configuration.EnvironmentKubernetes{}
		require.NoError(t, conf.SetDefaults())
		conf.Name = template.MustNewString("bifroest-{{.session.id}}")
		conf.ImagePullCredentials = template.MustNewString(`{{ fail "must not resolve credentials" }}`)
		repo := &KubernetesRepository{conf: conf, client: targetKubernetesBackend{host: "https://cluster", namespace: "default"}}
		first, err := repo.ResolveSessionTarget(ctx)
		require.NoError(t, err)
		for _, change := range []func(*configuration.EnvironmentKubernetes){
			func(c *configuration.EnvironmentKubernetes) { c.Name = template.MustNewString("other-name") },
			func(c *configuration.EnvironmentKubernetes) { c.Namespace = template.MustNewString("other-namespace") },
			func(c *configuration.EnvironmentKubernetes) {
				c.ServiceAccountName = template.MustNewString("other-service-account")
			},
			func(c *configuration.EnvironmentKubernetes) { c.Image = template.MustNewString("other-image") },
			func(c *configuration.EnvironmentKubernetes) { c.Group = template.MustNewString("1001") },
			func(c *configuration.EnvironmentKubernetes) { c.Privileged = template.BoolOf(true) },
		} {
			copyOfConf := *conf
			change(&copyOfConf)
			repo.conf = &copyOfConf
			got, err := repo.ResolveSessionTarget(ctx)
			require.NoError(t, err)
			require.NotEqual(t, first, got)
		}
		repo.conf = conf
		repo.client = targetKubernetesBackend{host: "https://other-cluster", namespace: "default"}
		other, err := repo.ResolveSessionTarget(ctx)
		require.NoError(t, err)
		require.NotEqual(t, first, other)
	})
}

func TestSshSessionTargetDoesNotLoadKeysAndUsesExecutionAddressRules(t *testing.T) {
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString("work.example")
	conf.User = template.MustNewString("  account  ")
	conf.IdentityFiles = template.MustNewStrings("/nonexistent/must-not-read")
	repo := &SshRepository{conf: conf}
	ctx := targetTestContext{ctx: t.Context()}
	first, err := repo.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	conf.Address = template.MustNewString("work.example:22")
	conf.User = template.MustNewString("account")
	same, err := repo.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	require.Equal(t, first, same)
	conf.Address = template.MustNewString("WORK.example:22")
	same, err = repo.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	require.Equal(t, first, same)
	conf.Address = template.MustNewString("work.example:23")
	other, err := repo.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	require.NotEqual(t, first, other)
	conf.Address = template.MustNewString("{{ fail `secret-do-not-log` }}")
	_, err = repo.ResolveSessionTarget(ctx)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret-do-not-log")
}

func TestSessionTargetResolverLookupCancellationAndManagementRights(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context()}
	first := &ManagementRepository{includingCredentials: false}
	target, err := first.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	other, err := (&ManagementRepository{includingCredentials: true}).ResolveSessionTarget(ctx)
	require.NoError(t, err)
	require.NotEqual(t, target, other)
	other, err = (&ManagementRepository{allowArtifactTransfer: true}).ResolveSessionTarget(ctx)
	require.NoError(t, err)
	require.NotEqual(t, target, other)
	resolver, ok := SessionTargetResolverFor(&RepositoryFacade{entries: map[configuration.FlowName]CloseableRepository{"work": first}}, "work")
	require.True(t, ok)
	require.Same(t, first, resolver)
	_, ok = SessionTargetResolverFor(&RepositoryFacade{}, "missing")
	require.False(t, ok)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = first.ResolveSessionTarget(targetTestContext{ctx: canceled})
	require.ErrorIs(t, err, context.Canceled)
}

// Keep imported interface contracts checked without requiring SSH contexts.
var _ SessionTargetResolver = (*DockerRepository)(nil)
var _ SessionTargetResolver = (*KubernetesRepository)(nil)
var _ connection.Context = targetTestContext{}
