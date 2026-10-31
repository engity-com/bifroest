package configuration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestFlowHttpKeepAliveUsesAuthenticatedTemplateAndLockedDuration(t *testing.T) {
	policy, err := (FlowHttp{}).ResolveKeepAlive(nil)
	require.NoError(t, err)
	require.Equal(t, HttpKeepAlive{Interval: 15 * time.Second}, policy)
	for _, entry := range []struct {
		source   string
		interval time.Duration
		locked   bool
	}{
		{"10s", 10 * time.Second, false}, {"!10s", 10 * time.Second, true},
		{`{{if .authenticated}}!1m{{else}}10s{{end}}`, time.Minute, true},
	} {
		var conf FlowHttp
		require.NoError(t, yaml.Unmarshal([]byte("keepAlive: '"+entry.source+"'"), &conf))
		require.NoError(t, conf.Validate())
		actual, err := conf.ResolveKeepAlive(map[string]any{"authenticated": true})
		require.NoError(t, err)
		require.Equal(t, HttpKeepAlive{Interval: entry.interval, Locked: entry.locked}, actual)
	}
}

func TestFlowHttpKeepAliveRejectsMistypedUnsafeAndPrivateTemplateOutput(t *testing.T) {
	for _, source := range []string{"null", "false", "10", "[]", "{}", "!10s"} {
		var conf FlowHttp
		require.Error(t, yaml.Unmarshal([]byte("keepAlive: "+source), &conf), source)
	}
	for _, value := range []string{"0s", "-1s", "999ms", "5m1ns", "1h", "!PRIVATE-TOKEN"} {
		conf := FlowHttp{KeepAlive: template.MustNewString(value)}
		err := conf.Validate()
		require.Error(t, err, value)
		require.NotContains(t, err.Error(), "PRIVATE-TOKEN")
	}
	conf := FlowHttp{KeepAlive: template.MustNewString("{{.private}}")}
	_, err := conf.ResolveKeepAlive(map[string]any{"private": "PRIVATE-TOKEN"})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "PRIVATE-TOKEN")
}
