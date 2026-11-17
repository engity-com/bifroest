package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestAuthorizationRememberMe(t *testing.T) {
	for _, tc := range []struct {
		value    string
		expected RememberMe
	}{
		{"forbidden", RememberMeForbidden}, {"false", RememberMeForbidden}, {"off", RememberMeForbidden}, {"no", RememberMeForbidden}, {"0", RememberMeForbidden}, {`""`, RememberMeForbidden},
		{"allowed", RememberMeAllowed}, {"true", RememberMeAllowed}, {"on", RememberMeAllowed}, {"yes", RememberMeAllowed}, {"1", RememberMeAllowed},
		{"allowedAndEnabledByDefault", RememberMeAllowedAndEnabledByDefault}, {"enforced", RememberMeEnforced},
	} {
		t.Run(tc.value, func(t *testing.T) {
			var conf Authorization
			require.NoError(t, yaml.Unmarshal([]byte("type: simple\nrememberMe: "+tc.value), &conf))
			require.Equal(t, tc.expected, conf.RememberMe)
			raw, err := yaml.Marshal(conf)
			require.NoError(t, err)
			require.Contains(t, string(raw), "rememberMe: "+tc.expected.String())
			var decoded Authorization
			require.NoError(t, yaml.Unmarshal(raw, &decoded))
			require.True(t, conf.IsEqualTo(decoded))
		})
	}
	var conf Authorization
	require.NoError(t, yaml.Unmarshal([]byte("type: simple"), &conf))
	require.False(t, conf.RememberMe.Allowed())
	for _, invalid := range []string{"sometimes", "2", "[]", "{}"} {
		require.Error(t, yaml.Unmarshal([]byte("type: simple\nrememberMe: "+invalid), &conf))
	}
	for _, mode := range []RememberMe{RememberMeForbidden, RememberMeAllowed, RememberMeAllowedAndEnabledByDefault, RememberMeEnforced} {
		require.Equal(t, mode.EnabledByDefault(), mode.Enabled("", false))
		require.Equal(t, mode.Allowed(), mode.Enabled("yes", true))
		require.Equal(t, mode == RememberMeEnforced, mode.Enabled("off", true))
	}
}

func TestAuthorizationRejectsRememberMeForNoneAndBifroest(t *testing.T) {
	for _, kind := range []string{"none", "bifroest"} {
		for _, value := range []string{"forbidden", "false", "off", "no", "0", "allowed", "true", "allowedAndEnabledByDefault", "enforced", `""`, "null", ""} {
			t.Run(kind+"/"+value, func(t *testing.T) {
				var conf Authorization
				require.ErrorContains(t, yaml.Unmarshal([]byte("type: "+kind+"\nrememberMe: "+value), &conf), "rememberMe")
			})
		}
	}
	for _, backend := range []AuthorizationV{&AuthorizationNone{}, &AuthorizationBifroest{}} {
		conf := Authorization{V: backend}
		require.False(t, conf.SupportsRememberMe())
		for _, mode := range []RememberMe{RememberMeForbidden, RememberMeAllowed, RememberMeAllowedAndEnabledByDefault, RememberMeEnforced} {
			conf.RememberMe = mode
			require.ErrorContains(t, conf.Validate(), "rememberMe")
			require.Equal(t, RememberMeForbidden, conf.RememberMePolicy())
			_, err := yaml.Marshal(conf)
			require.ErrorContains(t, err, "rememberMe")
		}
	}
}
