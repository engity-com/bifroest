package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestReloadReuseKeepsBackendCredentialsAndPolicyBoundaries(t *testing.T) {
	previous := &EnvironmentDocker{}
	require.NoError(t, previous.SetDefaults())
	before := Environment{V: previous}
	current := *previous
	current.Image = template.MustNewString("new-image")
	current.ImagePullCredentials = template.MustNewString("new-pull-credentials")
	require.True(t, EnvironmentCanReuse(before, Environment{V: &current}))
	for _, change := range []func(*EnvironmentDocker){
		func(c *EnvironmentDocker) { c.Host = template.MustNewString("tcp://different:2376") },
		func(c *EnvironmentDocker) { c.CertPath = template.MustNewString("/different") },
		func(c *EnvironmentDocker) { c.TlsVerify = template.BoolOf(true) },
		func(c *EnvironmentDocker) { c.User = template.MustNewString("different") },
		func(c *EnvironmentDocker) { c.Volumes = template.MustNewStrings("/different:/data") },
		func(c *EnvironmentDocker) { c.Privileged = template.BoolOf(true) },
		func(c *EnvironmentDocker) { c.PortForwardingAllowed = template.BoolOf(false) },
	} {
		copyOfCurrent := current
		change(&copyOfCurrent)
		require.False(t, EnvironmentCanReuse(before, Environment{V: &copyOfCurrent}))
	}
	require.False(t, EnvironmentCanReuse(before, Environment{V: &EnvironmentDummy{}}))
	require.False(t, EnvironmentCanReuse(Environment{}, Environment{}))
}
