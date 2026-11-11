//go:build unix || windows

package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLocalPamAccountResumeRequiresExplicitSupportedConfiguration(t *testing.T) {
	conf := &AuthorizationLocal{}
	require.NoError(t, conf.SetDefaults())
	require.False(t, conf.PamAccountResumeAllowed)
	conf.PamAccountResumeAllowed = true
	conf.PamService = ""
	require.Error(t, conf.Validate())
	conf.PamService = DefaultAuthorizationLocalPamService
	if localPamAccountResumeAvailable {
		require.NoError(t, conf.Validate())
		raw, err := yaml.Marshal(conf)
		require.NoError(t, err)
		var decoded AuthorizationLocal
		require.NoError(t, yaml.Unmarshal(raw, &decoded))
		require.True(t, conf.IsEqualTo(decoded))
		decoded.PamAccountResumeAllowed = false
		require.False(t, conf.IsEqualTo(decoded))
	} else {
		require.Error(t, conf.Validate(), "unsupported editions/platforms must not silently ignore opt-in")
	}
}
