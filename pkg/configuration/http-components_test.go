package configuration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHttpComponentsAndDirectSshAreIndependent(t *testing.T) {
	for mask := range 16 {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			var conf Configuration
			source := fmt.Sprintf("ssh: {enabled: %t}\nhttp:\n  webUi: {enabled: %t}\n  sshTunnel: {enabled: %t}\n  loginFlow: {enabled: %t}\n", mask&1 != 0, mask&2 != 0, mask&4 != 0, mask&8 != 0)
			require.NoError(t, conf.LoadFromYaml(strings.NewReader(source+httpTestFlows), ""))
			require.Equal(t, mask&1 != 0, conf.Ssh.IsEnabled())
			require.Equal(t, mask&2 != 0, conf.Http.WebUi.IsEnabled())
			require.Equal(t, mask&4 != 0, conf.Http.SshTunnel.IsEnabled())
			require.Equal(t, mask&8 != 0, conf.Http.LoginFlow.IsEnabled())
			require.False(t, conf.Http.IsEnabled(), "child switches must not enable HTTPS")
		})
	}
	var defaults Configuration
	require.NoError(t, defaults.LoadFromYaml(strings.NewReader("http: {}\n"+httpTestFlows), ""))
	require.True(t, defaults.Ssh.IsEnabled())
	require.True(t, defaults.Http.WebUi.IsEnabled())
	require.True(t, defaults.Http.SshTunnel.IsEnabled())
	require.True(t, defaults.Http.LoginFlow.IsEnabled())
	for _, component := range []string{"webUi", "sshTunnel", "loginFlow"} {
		for _, invalid := range []string{"null", "false", "{enabled: null}", "{enabled: 'false'}", "{enabld: false}", "{<<: {enabled: null}}"} {
			var conf Configuration
			require.Error(t, conf.LoadFromYaml(strings.NewReader("http: {"+component+": "+invalid+"}\n"+httpTestFlows), ""), component+": "+invalid)
		}
		var changed Configuration
		require.NoError(t, changed.LoadFromYaml(strings.NewReader("http: {"+component+": {enabled: false}}\n"+httpTestFlows), ""))
		require.False(t, defaults.Http.IsEqualTo(changed.Http))
	}
	for _, invalid := range []string{"null", "'false'", "{}"} {
		var conf Configuration
		require.Error(t, conf.LoadFromYaml(strings.NewReader("ssh: {enabled: "+invalid+"}\n"+httpTestFlows), ""))
	}
}
