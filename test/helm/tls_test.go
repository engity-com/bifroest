//go:build helm_integration

package helm_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func helm(t *testing.T, values map[string]any) ([]map[string]any, error) {
	t.Helper()
	dir := t.TempDir()
	raw, err := yaml.Marshal(values)
	require.NoError(t, err)
	path := filepath.Join(dir, "values.yaml")
	require.NoError(t, os.WriteFile(path, raw, 0600))
	cmd := exec.CommandContext(t.Context(), "helm", "template", "tls-test", "../../charts/bifroest", "-f", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, &renderError{string(output), err}
	}
	var documents []map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(output))
	for {
		var document map[string]any
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if len(document) != 0 {
			documents = append(documents, document)
		}
	}
	return documents, nil
}

type renderError struct {
	message string
	cause   error
}

func (this *renderError) Error() string { return this.message }
func (this *renderError) Unwrap() error { return this.cause }

func tlsValues(t *testing.T) map[string]any {
	t.Helper()
	var values map[string]any
	raw, err := os.ReadFile("../../charts/bifroest/values.yaml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &values))
	return values
}
func config(values map[string]any) map[string]any { return values["configuration"].(map[string]any) }
func profile(values map[string]any, acme bool) {
	c := config(values)
	p := map[string]any{}
	if acme {
		p["acme"] = map[string]any{"acceptTerms": true}
	} else {
		p["certificates"] = []any{map[string]any{"certificateFile": "/run/tls/tls.crt", "privateKeyFile": "/run/tls/tls.key"}}
	}
	c["tls"] = map[string]any{"public": p}
	c["http"] = map[string]any{"enabled": true, "addresses": []string{":8443"}, "domains": []string{"app.example.org"}, "tls": "public"}
}

func validateRenderedConfiguration(t *testing.T, documents []map[string]any) configuration.Configuration {
	t.Helper()
	found := false
	var conf configuration.Configuration
	for _, document := range documents {
		if document["kind"] != "Secret" {
			continue
		}
		data, ok := document["data"].(map[string]any)
		if !ok || data["configuration.yaml"] == nil {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(data["configuration.yaml"].(string))
		require.NoError(t, err)
		require.NoError(t, conf.LoadFromYaml(bytes.NewReader(raw), "rendered-helm-configuration"))
		found = true
	}
	require.True(t, found, "inline configuration must stay a Secret and pass the real Go resolver")
	return conf
}

func TestHelmTLSModesRenderAndPassTheGoConfigurationResolver(t *testing.T) {
	version, err := exec.CommandContext(t.Context(), "helm", "version", "--short").Output()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(version), "v4.3.2"), "chart contract pins Helm 4.3.2")
	lint := exec.CommandContext(t.Context(), "helm", "lint", "../../charts/bifroest", "--strict")
	output, err := lint.CombinedOutput()
	require.NoError(t, err, "%s", output)
	for _, mode := range []string{"default", "profile", "yaml-string", "legacy", "inline-tls", "empty-tls", "named-dummy", "direct-acme", "challenge-only", "challenge-only-standalone", "reverse-proxy", "monitoring-profile", "monitoring-inline", "monitoring-inline-dummy", "monitoring-empty", "monitoring-inline-acme"} {
		t.Run(mode, func(t *testing.T) {
			values := tlsValues(t)
			c := config(values)
			switch mode {
			case "profile", "yaml-string":
				profile(values, false)
				if mode == "yaml-string" {
					raw, err := yaml.Marshal(c)
					require.NoError(t, err)
					values["configuration"] = string(raw)
				}
			case "legacy":
				c["http"] = map[string]any{"enabled": true, "domains": []string{"app.example.org"}, "tls": map[string]any{"certificates": []any{map[string]any{"certificateFile": "/run/tls/cert", "privateKeyFile": "/run/tls/key"}}}}
			case "inline-tls":
				c["http"] = map[string]any{"enabled": true, "domains": []string{"app.example.org"}, "tls": map[string]any{
					"minVersion": "1.3", "dummy": true,
				}}
			case "named-dummy":
				c["tls"] = map[string]any{"testing": map[string]any{"dummy": true, "minVersion": "1.3"}}
				c["http"] = map[string]any{"enabled": true, "domains": []string{"app.example.org"}, "tls": "testing"}
			case "empty-tls":
				c["http"] = map[string]any{"enabled": true, "domains": []string{"app.example.org"}, "tls": map[string]any{}}
			case "direct-acme", "challenge-only", "challenge-only-standalone", "monitoring-inline-acme":
				profile(values, true)
				httpService := values["service"].(map[string]any)["http"].(map[string]any)
				httpService["enabled"], httpService["publishNotReadyAddresses"] = true, true
				values["networkPolicy"].(map[string]any)["httpPeers"] = []any{map[string]any{"ipBlock": map[string]any{"cidr": "0.0.0.0/0"}}}
				if mode == "challenge-only" || mode == "challenge-only-standalone" {
					c["http"].(map[string]any)["enabled"] = "acmeTlsAlpnOnly"
				}
				if mode == "challenge-only" {
					c["monitoring"].(map[string]any)["tls"] = "public"
					c["monitoring"].(map[string]any)["domains"] = []string{"app.example.org"}
					values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
				}
				if mode == "monitoring-inline-acme" {
					c["monitoring"].(map[string]any)["tls"] = map[string]any{"acme": map[string]any{"acceptTerms": true}}
					c["monitoring"].(map[string]any)["domains"] = []string{"metrics.example.net"}
					values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
				}
			case "reverse-proxy":
				c["http"] = map[string]any{"enabled": true, "domains": []string{"app.example.org"}, "upstream": map[string]any{"mode": "reverseProxy", "trustedPeers": []string{"10.0.0.0/24"}}}
			case "monitoring-profile":
				profile(values, false)
				c["monitoring"].(map[string]any)["tls"] = "public"
				c["monitoring"].(map[string]any)["domains"] = []string{"metrics.example.net"}
				values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
			case "monitoring-inline":
				c["monitoring"].(map[string]any)["tls"] = map[string]any{"certificates": []any{map[string]any{"certificateFile": "/run/tls/cert", "privateKeyFile": "/run/tls/key"}}}
				c["monitoring"].(map[string]any)["domains"] = []string{"metrics.example.net"}
				values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
			case "monitoring-inline-dummy", "monitoring-empty":
				definition := map[string]any{}
				if mode == "monitoring-inline-dummy" {
					definition = map[string]any{"dummy": true, "minVersion": "1.2", "reloadInterval": "7s"}
				}
				c["monitoring"].(map[string]any)["tls"] = definition
				c["monitoring"].(map[string]any)["domains"] = []string{"metrics.example.net"}
				values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
			}
			documents, err := helm(t, values)
			require.NoError(t, err)
			validateRenderedConfiguration(t, documents)
			httpServices := 0
			for _, document := range documents {
				if document["kind"] != "Service" {
					continue
				}
				spec := document["spec"].(map[string]any)
				ports, _ := spec["ports"].([]any)
				require.NotEqual(t, "tls-test-bifroest-tls", document["metadata"].(map[string]any)["name"])
				if document["metadata"].(map[string]any)["name"] == "tls-test-bifroest-http" {
					httpServices++
					require.Equal(t, true, spec["publishNotReadyAddresses"])
					require.Len(t, ports, 1)
					port := ports[0].(map[string]any)
					require.Equal(t, "http", port["name"])
					require.EqualValues(t, 443, port["port"])
					require.Equal(t, "http", port["targetPort"])
				}
				for _, raw := range ports {
					port := raw.(map[string]any)
					require.NotEqual(t, "monitoring", port["targetPort"])
				}
			}
			if mode == "direct-acme" || mode == "challenge-only" || mode == "challenge-only-standalone" || mode == "monitoring-inline-acme" {
				require.Equal(t, 1, httpServices)
			} else {
				require.Zero(t, httpServices)
			}
		})
	}
}

func TestHelmHTTPServiceUsesCommonServiceSettingsAndDedicatedPeers(t *testing.T) {
	for _, serviceType := range []string{"ClusterIP", "NodePort", "LoadBalancer"} {
		t.Run(serviceType, func(t *testing.T) {
			values := tlsValues(t)
			profile(values, false)
			config(values)["http"].(map[string]any)["addresses"] = []string{":9443"}
			httpService := values["service"].(map[string]any)["http"].(map[string]any)
			httpService["enabled"], httpService["type"], httpService["targetPort"] = true, serviceType, 9443
			httpService["annotations"] = map[string]any{"owner": "tls-test"}
			httpService["sessionAffinity"], httpService["publishNotReadyAddresses"] = "ClientIP", false
			httpService["loadBalancerSourceRanges"] = []string{"198.51.100.0/24"}
			peers := []any{map[string]any{"ipBlock": map[string]any{"cidr": "198.51.100.0/24"}}}
			values["networkPolicy"].(map[string]any)["httpPeers"] = peers
			documents, err := helm(t, values)
			require.NoError(t, err)
			validateRenderedConfiguration(t, documents)
			serviceFound, portFound, policyFound := false, false, false
			for _, document := range documents {
				spec, _ := document["spec"].(map[string]any)
				switch document["kind"] {
				case "Service":
					metadata := document["metadata"].(map[string]any)
					if metadata["name"] != "tls-test-bifroest-http" {
						continue
					}
					serviceFound = true
					require.Equal(t, "tls-test", metadata["annotations"].(map[string]any)["owner"])
					require.Equal(t, serviceType, spec["type"])
					require.Equal(t, "ClientIP", spec["sessionAffinity"])
					require.Equal(t, false, spec["publishNotReadyAddresses"])
					ports := spec["ports"].([]any)
					require.Equal(t, []any{map[string]any{"name": "http", "port": 443, "targetPort": "http", "protocol": "TCP"}}, ports)
					if serviceType == "LoadBalancer" {
						require.Equal(t, []any{"198.51.100.0/24"}, spec["loadBalancerSourceRanges"])
					} else {
						require.NotContains(t, spec, "loadBalancerSourceRanges")
					}
				case "StatefulSet":
					pod := spec["template"].(map[string]any)["spec"].(map[string]any)
					container := pod["containers"].([]any)[0].(map[string]any)
					for _, value := range container["ports"].([]any) {
						port := value.(map[string]any)
						if port["name"] == "http" {
							portFound = true
							require.EqualValues(t, 9443, port["containerPort"])
						}
					}
				case "NetworkPolicy":
					for _, value := range spec["ingress"].([]any) {
						rule := value.(map[string]any)
						port := rule["ports"].([]any)[0].(map[string]any)
						if port["port"] == 9443 {
							policyFound = true
							require.Equal(t, "TCP", port["protocol"])
							require.Equal(t, peers, rule["from"])
						}
					}
				}
			}
			require.True(t, serviceFound)
			require.True(t, portFound)
			require.True(t, policyFound)
		})
	}
}

func TestHelmExternalConfigurationIsMountedWithoutLookup(t *testing.T) {
	for _, source := range []string{"secret:existing", "configMap:existing"} {
		t.Run(source, func(t *testing.T) {
			values := tlsValues(t)
			profile(values, false)
			// External source contents are validated with the real resolver, not
			// fetched or interpreted by Helm during rendering.
			raw, err := yaml.Marshal(config(values))
			require.NoError(t, err)
			var conf configuration.Configuration
			require.NoError(t, conf.LoadFromYaml(bytes.NewReader(raw), source))
			values["configuration"] = source
			documents, err := helm(t, values)
			require.NoError(t, err)
			for _, document := range documents {
				require.NotEqual(t, "Secret", document["kind"])
			}
		})
	}
}

func TestHelmRejectsInvalidTLSAndExposureCombinations(t *testing.T) {
	for _, mode := range []string{"unknown", "type", "null", "enabled-inline", "enabled-named", "allowed-names-inline", "allowed-names-named", "allowed-names-monitoring", "monitoring-inline-no-domains", "absent-direct", "chain", "scheme", "private-port", "ssh-port", "replicas", "bootstrap", "http-peers", "http-target", "removed-challenge", "schema-port", "schema-target", "schema-http", "service-mode", "mode-unknown", "mode-string-bool", "mode-shape", "alpn-file", "alpn-proxy", "alpn-missing-tls", "alpn-no-domains", "disabled-http", "acme-port", "separate-tls-service"} {
		t.Run(mode, func(t *testing.T) {
			values := tlsValues(t)
			automation := mode == "replicas" || mode == "bootstrap" || mode == "http-peers" || strings.HasPrefix(mode, "alpn-") || mode == "acme-port"
			profile(values, automation && mode != "alpn-file")
			c := config(values)
			httpService := values["service"].(map[string]any)["http"].(map[string]any)
			httpService["enabled"], httpService["publishNotReadyAddresses"] = true, true
			if strings.HasPrefix(mode, "alpn-") {
				c["http"].(map[string]any)["enabled"] = "acmeTlsAlpnOnly"
			}
			if automation && mode != "http-peers" {
				values["networkPolicy"].(map[string]any)["httpPeers"] = []any{map[string]any{"ipBlock": map[string]any{"cidr": "0.0.0.0/0"}}}
			}
			switch mode {
			case "unknown":
				c["http"].(map[string]any)["tls"] = "missing"
			case "type":
				c["http"].(map[string]any)["tls"] = 1
			case "null":
				c["http"].(map[string]any)["tls"] = nil
			case "enabled-inline":
				c["http"].(map[string]any)["tls"] = map[string]any{"enabled": true}
			case "enabled-named":
				c["tls"].(map[string]any)["public"].(map[string]any)["enabled"] = false
			case "allowed-names-inline":
				c["http"].(map[string]any)["tls"] = map[string]any{"dummy": true, "allowedNames": []string{"app.example.org"}}
			case "allowed-names-named":
				c["tls"].(map[string]any)["public"].(map[string]any)["allowedNames"] = []string{"app.example.org"}
			case "allowed-names-monitoring":
				c["monitoring"].(map[string]any)["tls"] = map[string]any{"allowedNames": []string{"metrics.example.net"}}
				values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
			case "monitoring-inline-no-domains":
				c["monitoring"].(map[string]any)["tls"] = map[string]any{"dummy": true}
				values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
			case "absent-direct":
				delete(c["http"].(map[string]any), "tls")
			case "chain":
				c["tls"].(map[string]any)["public"] = "another"
			case "scheme":
				c["monitoring"].(map[string]any)["tls"] = "public"
			case "private-port":
				httpService["targetPort"] = 9090
			case "ssh-port":
				httpService["targetPort"] = 2222
			case "replicas":
				values["replicaCount"] = 2
			case "bootstrap":
				httpService["publishNotReadyAddresses"] = false
			case "http-peers":
				values["networkPolicy"].(map[string]any)["httpPeers"] = []any{}
			case "http-target":
				httpService["targetPort"] = 9443
			case "removed-challenge":
				c["tlsChallenge"] = map[string]any{"addresses": []string{":8443"}}
			case "schema-port":
				httpService["port"] = 0
			case "schema-target":
				httpService["targetPort"] = 65536
			case "schema-http":
				values["service"].(map[string]any)["http"] = nil
			case "service-mode":
				httpService["enabled"] = "acmeTlsAlpnOnly"
			case "mode-unknown":
				c["http"].(map[string]any)["enabled"] = "unknown"
			case "mode-string-bool":
				c["http"].(map[string]any)["enabled"] = "true"
			case "mode-shape":
				c["http"].(map[string]any)["enabled"] = []any{}
			case "alpn-proxy":
				c["http"].(map[string]any)["upstream"] = map[string]any{"mode": "reverseProxy", "trustedPeers": []string{"127.0.0.1"}}
			case "alpn-missing-tls":
				delete(c["http"].(map[string]any), "tls")
			case "alpn-no-domains":
				delete(c["http"].(map[string]any), "domains")
			case "disabled-http":
				c["http"].(map[string]any)["enabled"] = false
			case "acme-port":
				httpService["port"] = 80
			case "separate-tls-service":
				values["service"].(map[string]any)["tls"] = map[string]any{"enabled": true}
			}
			_, err := helm(t, values)
			require.Error(t, err)
		})
	}
}

func TestHelmACMEPresenceMatchesTheGoResolver(t *testing.T) {
	for _, consumer := range []string{"named", "http", "monitoring"} {
		for _, test := range []struct {
			name    string
			value   any
			enabled bool
			invalid bool
		}{
			{name: "absent"},
			{name: "null", value: nil},
			{name: "accepted", value: map[string]any{"acceptTerms": true}, enabled: true},
			{name: "empty", value: map[string]any{}, invalid: true},
			{name: "without-consent", value: map[string]any{"acceptTerms": false}, invalid: true},
			{name: "removed-enabled-true", value: map[string]any{"enabled": true, "acceptTerms": true}, invalid: true},
			{name: "removed-enabled-false", value: map[string]any{"enabled": false}, invalid: true},
			{name: "false", value: false, invalid: true},
			{name: "array", value: []any{}, invalid: true},
		} {
			t.Run(consumer+"/"+test.name, func(t *testing.T) {
				values := tlsValues(t)
				profile(values, false)
				c := config(values)
				definition := c["tls"].(map[string]any)["public"].(map[string]any)
				switch consumer {
				case "http":
					c["http"].(map[string]any)["tls"] = definition
					delete(c, "tls")
				case "monitoring":
					// Keep HTTP file-only so it remains the validation transport.
					definition = map[string]any{"certificates": definition["certificates"]}
					c["monitoring"].(map[string]any)["tls"] = definition
					c["monitoring"].(map[string]any)["domains"] = []string{"metrics.example.org"}
					values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
				}
				if test.name != "absent" {
					definition["acme"] = test.value
				}
				httpService := values["service"].(map[string]any)["http"].(map[string]any)
				httpService["enabled"] = true
				httpService["publishNotReadyAddresses"] = test.enabled
				values["networkPolicy"].(map[string]any)["httpPeers"] = []any{map[string]any{"ipBlock": map[string]any{"cidr": "0.0.0.0/0"}}}
				if !test.enabled && !test.invalid {
					values["replicaCount"] = 2
				}
				documents, err := helm(t, values)
				if test.invalid {
					require.Error(t, err)
					raw, err := yaml.Marshal(c)
					require.NoError(t, err)
					var conf configuration.Configuration
					require.Error(t, conf.LoadFromYaml(bytes.NewReader(raw), ""))
					return
				}
				require.NoError(t, err)
				validateRenderedConfiguration(t, documents)
			})
		}
	}
}

func TestHelmTLSDefaultSelectionMatchesTheGoResolver(t *testing.T) {
	for _, consumer := range []string{"http", "monitoring"} {
		for _, definition := range []string{"absent", "files", "acme"} {
			for _, selection := range []string{"omitted", "empty", "null", "inline", "named"} {
				for _, representation := range []string{"object", "yaml"} {
					t.Run(consumer+"/"+definition+"/"+selection+"/"+representation, func(t *testing.T) {
						values := tlsValues(t)
						profile(values, false)
						c := config(values)
						definitions := c["tls"].(map[string]any)
						switch definition {
						case "files":
							definitions["default"] = definitions["public"]
						case "acme":
							definitions["default"] = map[string]any{"acme": map[string]any{"acceptTerms": true}}
						}
						listener := c[consumer].(map[string]any)
						listener["domains"] = []string{"app.example.org"}
						if consumer == "http" {
							listener["upstream"] = map[string]any{"mode": "reverseProxy", "trustedPeers": []string{"127.0.0.1"}}
						}
						delete(listener, "tls")
						switch selection {
						case "empty":
							listener["tls"] = ""
						case "null":
							listener["tls"] = nil
						case "inline":
							listener["tls"] = map[string]any{}
						case "named":
							listener["tls"] = "default"
						}
						automatic := selection == "empty" || selection == "omitted" && consumer == "http"
						enabled := selection == "inline" || selection == "named" || automatic && definition != "absent"
						acmeActive := definition == "acme" && (automatic || selection == "named")
						service := values["service"].(map[string]any)["http"].(map[string]any)
						service["enabled"], service["publishNotReadyAddresses"] = true, acmeActive
						if acmeActive {
							values["networkPolicy"].(map[string]any)["httpPeers"] = []any{map[string]any{"ipBlock": map[string]any{"cidr": "0.0.0.0/0"}}}
						} else {
							values["replicaCount"] = 2
						}
						if consumer == "monitoring" && enabled {
							values["monitoring"].(map[string]any)["scheme"] = "HTTPS"
						}
						if representation == "yaml" {
							raw, err := yaml.Marshal(c)
							require.NoError(t, err)
							values["configuration"] = string(raw)
						}
						documents, err := helm(t, values)
						if selection == "named" && definition == "absent" {
							require.Error(t, err)
							return
						}
						require.NoError(t, err)
						conf := validateRenderedConfiguration(t, documents)
						selected := conf.Http.Tls
						if consumer == "monitoring" {
							selected = conf.Monitoring.Tls
						}
						require.Equal(t, enabled, selected.IsEnabled())
						if enabled {
							effective, err := selected.ServerDefinition()
							require.NoError(t, err)
							require.Equal(t, acmeActive, effective.Acme.IsEnabled())
						}
					})
				}
			}
		}
	}
}
