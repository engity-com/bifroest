package service

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func selectionTestConfiguration(t *testing.T, conf configuration.Configuration, change func(map[string]any)) configuration.Configuration {
	t.Helper()
	raw, err := yaml.Marshal(conf)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &fields))
	change(fields)
	raw, err = yaml.Marshal(fields)
	require.NoError(t, err)
	var restored configuration.Configuration
	require.NoError(t, restored.LoadFromYaml(bytes.NewReader(raw), ""))
	return restored
}

func TestDefaultTLSSelectionsUseOneManagerAndRespectExplicitOptOut(t *testing.T) {
	for _, test := range []struct {
		http, monitoring string
	}{
		{"omitted", "omitted"},
		{"empty", "empty"},
		{"null", "empty"},
		{"empty", "null"},
	} {
		t.Run(test.http+"/"+test.monitoring, func(t *testing.T) {
			conf := sharedTLSConfiguration(t)
			conf.Tls["default"] = conf.Tls["shared"]
			delete(conf.Tls, "shared")
			conf = selectionTestConfiguration(t, conf, func(fields map[string]any) {
				for consumer, selection := range map[string]string{"http": test.http, "monitoring": test.monitoring} {
					listener := fields[consumer].(map[string]any)
					delete(listener, "tls")
					switch selection {
					case "empty":
						listener["tls"] = ""
					case "null":
						listener["tls"] = nil
					}
					if consumer == "http" && selection == "null" {
						listener["upstream"] = map[string]any{"mode": "reverseProxy", "trustedPeers": []string{"127.0.0.1"}}
					}
				}
			})
			svc := prepareHTTPListenerTestService(t, conf)
			require.Len(t, svc.tlsManagers, 1)
			require.NotNil(t, svc.tlsManagers["tls:default"])
			require.Equal(t, test.http != "null", svc.tlsBindings["http"] != nil)
			require.Equal(t, test.monitoring == "empty", svc.tlsBindings["monitoring"] != nil)
			require.NoError(t, svc.prepareTLSBindings(t.Context()))
			for _, binding := range svc.tlsBindings {
				require.True(t, binding.Ready())
			}
		})
	}
}

func TestExplicitNullAuditlogDoesNotUseTheDefaultRecorder(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	httpListenerTestCertificate(t, &conf, nil)
	root := t.TempDir()
	logger := configureDefaultTestAuditlog(&conf)
	logger.IdentityFile = filepath.Join(root, "audit-key")
	logger.Directory = filepath.Join(root, "journal")
	logger.Recording.Directory = filepath.Join(root, "recordings")
	conf = selectionTestConfiguration(t, conf, func(fields map[string]any) {
		fields["flows"].([]any)[0].(map[string]any)["auditlog"] = nil
	})
	svc := prepareHTTPListenerTestService(t, conf)
	require.NotNil(t, svc.auditRecorders[configuration.DefaultAuditlogName])
	name := conf.Flows[0].Name
	require.Empty(t, svc.flowAuditlogs[name])
	require.IsType(t, audit.NewNoopRecorder(), svc.flowAuditRecorders[name])
}
