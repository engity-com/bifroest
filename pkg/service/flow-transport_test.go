package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestSshServiceHonorsFlowTransportConfiguration(t *testing.T) {
	no := false
	for _, test := range []struct {
		name      string
		configure func(*configuration.Configuration)
		accepted  bool
	}{
		{name: "existing defaults", accepted: true},
		{name: "HTTP disabled independently", configure: func(c *configuration.Configuration) { c.Flows[0].Http.Enabled = &no }, accepted: true},
		{name: "SSH disabled", configure: func(c *configuration.Configuration) { c.Flows[0].Ssh.Enabled = &no }},
		{name: "SSH name excluded", configure: func(c *configuration.Configuration) {
			c.Flows[0].Requirement.Ssh.ExcludedRequestingName = common.MustNewRegexp(`^restricted-key-user$`)
		}},
		{name: "HTTP name rule ignored", configure: func(c *configuration.Configuration) {
			c.Flows[0].Requirement.Http.ExcludedRequestingName = common.MustNewRegexp(`^restricted-key-user$`)
		}, accepted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, test.configure)
			client, err := server.dial()
			if client != nil {
				require.NoError(t, client.Close())
			}
			if test.accepted {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
