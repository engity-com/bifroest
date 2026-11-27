package charts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func documentedChartValues(t *testing.T, page, title string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", filepath.FromSlash(page)))
	require.NoError(t, err)
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	_, remaining, found := strings.Cut(text, "```yaml title=\""+title+"\"\n")
	require.True(t, found, "missing documented example %q in %s", title, page)
	block, _, found := strings.Cut(remaining, "```")
	require.True(t, found, "unclosed documented example %q in %s", title, page)
	return block
}

func documentedGatewayWithTestCredentials(t *testing.T, raw []byte) []byte {
	t.Helper()
	// Validate the exact rendered settings with synthetic mounted files, never
	// operator credentials or fixed paths on the machine running the test.
	directory := t.TempDir()
	for _, name := range []string{"gateway-clients.pub", "id_target", "target_known_hosts"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		key, err := ssh.NewPublicKey(public)
		require.NoError(t, err)
		var data []byte
		switch name {
		case "gateway-clients.pub":
			data = ssh.MarshalAuthorizedKey(key)
		case "id_target":
			block, err := ssh.MarshalPrivateKey(private, "documentation test")
			require.NoError(t, err)
			data = pem.EncodeToMemory(block)
		case "target_known_hosts":
			data = []byte(knownhosts.Line([]string{"target.example.org"}, key) + "\n")
		}
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), data, 0600))
		require.Contains(t, string(raw), "/run/bifroest/gateway/"+name)
	}
	return bytes.ReplaceAll(raw, []byte("/run/bifroest/gateway/"), []byte(filepath.ToSlash(directory)+"/"))
}

func TestDocumentedHelmInstallationAndOptionalValues(t *testing.T) {
	helm := testHelm(t)
	gateway := documentedChartValues(t, "setup/in-kubernetes.md", "values.yaml")
	ingress := documentedChartValues(t, "setup/in-kubernetes.md", "ingress-values.yaml")
	monitoring := documentedChartValues(t, "guides/monitoring.md", "monitoring-values.yaml")
	acme := documentedChartValues(t, "setup/in-kubernetes.md", "acme-values.yaml")
	replicas := documentedChartValues(t, "setup/operations.md", "Additional Helm values")
	for _, test := range []struct {
		name                string
		values              []string
		ingress, monitoring bool
		replicas            int32
	}{
		{"ssh-gateway", []string{gateway}, false, false, 1},
		{"http-ingress", []string{gateway, ingress}, true, false, 1},
		{"prometheus", []string{gateway, monitoring}, false, true, 1},
		{"ingress-and-prometheus", []string{gateway, ingress, monitoring}, true, true, 1},
		{"two-replicas", []string{gateway, ingress, monitoring, replicas}, true, true, 2},
		{"direct-acme", []string{gateway, acme}, false, false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			objects := renderProject(t, helm, test.values...)
			state := projectObject[*appsv1.StatefulSet](t, objects)
			require.Equal(t, test.replicas, *state.Spec.Replicas)
			require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, state.Spec.Template.Spec.SecurityContext.SeccompProfile.Type)
			require.Len(t, state.Spec.VolumeClaimTemplates, 1)
			require.Equal(t, "10Gi", state.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests.Storage().String())
			var credentials *corev1.SecretVolumeSource
			for _, volume := range state.Spec.Template.Spec.Volumes {
				if volume.Name == "gateway" {
					credentials = volume.Secret
				}
			}
			require.NotNil(t, credentials)
			require.Equal(t, "bifroest-gateway", credentials.SecretName)
			require.EqualValues(t, 0440, *credentials.DefaultMode)
			var parsed configuration.Configuration
			raw := documentedGatewayWithTestCredentials(t, projectConfiguration(t, objects))
			require.NoError(t, parsed.LoadFromYaml(bytes.NewReader(raw), ""))
			if test.ingress {
				require.False(t, parsed.Http.Tls.IsEnabled())
				route := projectObject[*networkingv1.Ingress](t, objects)
				require.Equal(t, "gateway.example.org", route.Spec.Rules[0].Host)
				require.Equal(t, "bifroest-public-tls", route.Spec.TLS[0].SecretName)
				require.Equal(t, "traefik", *route.Spec.IngressClassName)
			}
			policy := projectObject[*networkingv1.NetworkPolicy](t, objects)
			if test.monitoring {
				require.Equal(t, "true", state.Spec.Template.Annotations["prometheus.io/scrape"])
				require.Equal(t, "9090", state.Spec.Template.Annotations["prometheus.io/port"])
			}
			for _, rule := range policy.Spec.Ingress {
				if rule.Ports[0].Port.IntVal == 8080 || rule.Ports[0].Port.IntVal == 9090 {
					require.Len(t, rule.From, 1)
					require.NotNil(t, rule.From[0].NamespaceSelector)
					require.NotNil(t, rule.From[0].PodSelector)
				}
			}
		})
	}
}

func TestDocumentedGatewayAlsoWorksAsCompleteConfigurationString(t *testing.T) {
	helm := testHelm(t)
	gateway := documentedChartValues(t, "setup/in-kubernetes.md", "values.yaml")
	baseline := renderProject(t, helm, gateway)
	raw := projectConfiguration(t, baseline)
	values, err := yaml.Marshal(map[string]any{"configuration": string(raw)})
	require.NoError(t, err)
	objects := renderProject(t, helm, gateway, string(values))
	require.Equal(t, raw, projectConfiguration(t, objects))
}
