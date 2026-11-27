package charts

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	sigyaml "sigs.k8s.io/yaml"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func projectSource() string { return filepath.Join("..", "..", "..", "charts", "bifroest") }

func TestProjectChartPackagesAndUsesValidDenyByDefaultConfiguration(t *testing.T) {
	license, err := os.ReadFile(filepath.Join(projectSource(), "LICENSE"))
	require.NoError(t, err)
	projectLicense, err := os.ReadFile(filepath.Join("..", "..", "..", "LICENSE"))
	require.NoError(t, err)
	require.Equal(t, strings.TrimSpace(string(projectLicense)), strings.TrimSpace(string(license)))
	chart, err := Build(t.Context(), os.DirFS(projectSource()), "1.2.3", time.Unix(1700000000, 0))
	require.NoError(t, err)
	require.NotEmpty(t, chart.Data)
	raw, err := os.ReadFile(filepath.Join(projectSource(), "values.yaml"))
	require.NoError(t, err)
	var values struct {
		Configuration yaml.Node `yaml:"configuration"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &values))
	var config configuration.Configuration
	require.NoError(t, values.Configuration.Decode(&config))
	require.NoError(t, config.Validate())
	require.True(t, config.Monitoring.IsEnabled())
	require.Equal(t, "/var/lib/engity/bifroest/sessions", config.Session.V.(*configuration.SessionFs).Storage)
	auth := config.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
	require.Empty(t, auth.Entries, "the default must not provision working login credentials")
}

func TestProjectChartExcludesPrivateFilesWithRealHelm(t *testing.T) {
	helm := testHelm(t)
	directory := filepath.Join(t.TempDir(), "bifroest")
	require.NoError(t, os.CopyFS(directory, os.DirFS(projectSource())))
	baseline, err := Build(t.Context(), os.DirFS(directory), "1.2.3", testChartTime())
	require.NoError(t, err)
	for _, name := range []string{
		"private.key", ".env", ".env.production", ".git/config", ".idea/workspace.xml", ".vscode/settings.json",
		"templates/private.key", "templates/private.pem", "templates/private.p12", "templates/private.pfx",
		"templates/statefulset.yaml.bak", "templates/statefulset.yaml.orig", "templates/statefulset.yaml~",
		"templates/statefulset.yaml.swp", "templates/statefulset.yaml.swo", "templates/statefulset.yaml.tmp",
		"templates/.hidden.yaml", "templates/nested/.env", "templates/nested/private.key",
	} {
		filename := filepath.Join(directory, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(filename), 0700))
		require.NoError(t, os.WriteFile(filename, []byte("SYNTHETIC-SECRET-NOT-A-REAL-KEY"), 0600))
	}
	chart, err := Build(t.Context(), os.DirFS(directory), "1.2.3", testChartTime())
	require.NoError(t, err)
	require.Equal(t, baseline.Data, chart.Data, "local credentials and editor files do not affect the chart")

	destination := t.TempDir()
	output, err := exec.CommandContext(t.Context(), helm, "package", directory, "--version", "1.2.3", "--app-version", "1.2.3", "--destination", destination).CombinedOutput()
	require.NoError(t, err, "%s", output)
	raw, err := os.ReadFile(filepath.Join(destination, "bifroest-1.2.3.tgz"))
	require.NoError(t, err)
	goFiles, helmFiles := chartArchiveFiles(t, chart.Data), chartArchiveFiles(t, raw)
	require.Len(t, helmFiles, len(goFiles))
	for name := range goFiles {
		require.Contains(t, helmFiles, name, "Go and Helm agree on the intended chart file set")
	}
}

func TestProjectChartWithRealHelm(t *testing.T) {
	helm := testHelm(t)
	output, err := exec.CommandContext(t.Context(), helm, "lint", "--strict", projectSource()).CombinedOutput()
	require.NoError(t, err, "%s", output)

	t.Run("defaults", func(t *testing.T) {
		objects := renderProject(t, helm, "")
		state := projectObject[*appsv1.StatefulSet](t, objects)
		require.EqualValues(t, 1, *state.Spec.Replicas)
		require.Equal(t, appsv1.RetainPersistentVolumeClaimRetentionPolicyType, state.Spec.PersistentVolumeClaimRetentionPolicy.WhenDeleted)
		require.Equal(t, appsv1.RetainPersistentVolumeClaimRetentionPolicyType, state.Spec.PersistentVolumeClaimRetentionPolicy.WhenScaled)
		require.Len(t, state.Spec.VolumeClaimTemplates, 1)
		require.Equal(t, "data", state.Spec.VolumeClaimTemplates[0].Name)
		require.False(t, *state.Spec.Template.Spec.AutomountServiceAccountToken)
		require.True(t, *state.Spec.Template.Spec.SecurityContext.RunAsNonRoot)
		require.NotNil(t, state.Spec.Template.Spec.SecurityContext.SeccompProfile)
		require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, state.Spec.Template.Spec.SecurityContext.SeccompProfile.Type)
		require.NotContains(t, state.Spec.Template.Annotations, "prometheus.io/scrape")
		require.Equal(t, "proof-bifroest", state.Name)
		require.Equal(t, "bifroest", state.Labels["app.kubernetes.io/name"])
		container := state.Spec.Template.Spec.Containers[0]
		require.False(t, *container.SecurityContext.AllowPrivilegeEscalation)
		require.True(t, *container.SecurityContext.ReadOnlyRootFilesystem)
		require.Equal(t, []corev1.Capability{"ALL"}, container.SecurityContext.Capabilities.Drop)
		require.Equal(t, "/ready", container.StartupProbe.HTTPGet.Path)
		require.Equal(t, "/ready", container.ReadinessProbe.HTTPGet.Path)
		require.Equal(t, "/status", container.LivenessProbe.HTTPGet.Path)
		for _, object := range objects {
			if service, ok := object.(*corev1.Service); ok {
				for _, port := range service.Spec.Ports {
					require.NotEqual(t, "monitoring", port.Name)
				}
			}
		}
		config := projectConfiguration(t, objects)
		var parsed configuration.Configuration
		require.NoError(t, parsed.LoadFromYaml(bytes.NewReader(config), ""))
	})

	t.Run("custom-seccomp-profile", func(t *testing.T) {
		objects := renderProject(t, helm, "podSecurityContext:\n  seccompProfile:\n    type: Localhost\n    localhostProfile: bifroest/profile.json\n")
		state := projectObject[*appsv1.StatefulSet](t, objects)
		profile := state.Spec.Template.Spec.SecurityContext.SeccompProfile
		require.NotNil(t, profile)
		require.Equal(t, corev1.SeccompProfileTypeLocalhost, profile.Type)
		require.NotNil(t, profile.LocalhostProfile)
		require.Equal(t, "bifroest/profile.json", *profile.LocalhostProfile)
	})

	t.Run("replicas-external-secret-and-tls-mount", func(t *testing.T) {
		objects := renderProject(t, helm, `
replicaCount: 3
configuration: secret:gateway-config
image:
  tag: extended-1.2.3
persistence:
  storageClass: "-"
podDisruptionBudget:
  enabled: true
extraVolumes:
  - name: tls
    secret:
      secretName: gateway-tls
extraVolumeMounts:
  - name: tls
    mountPath: /run/bifroest/tls
    readOnly: true
`)
		state := projectObject[*appsv1.StatefulSet](t, objects)
		require.EqualValues(t, 3, *state.Spec.Replicas)
		require.Equal(t, "", *state.Spec.VolumeClaimTemplates[0].Spec.StorageClassName)
		require.Equal(t, "gateway-config", state.Spec.Template.Spec.Volumes[0].Secret.SecretName)
		require.Equal(t, "ghcr.io/engity-com/bifroest:extended-1.2.3", state.Spec.Template.Spec.Containers[0].Image)
		for _, mount := range state.Spec.Template.Spec.Containers[0].VolumeMounts {
			require.Empty(t, mount.SubPath)
		}
		for _, object := range objects {
			_, secret := object.(*corev1.Secret)
			require.False(t, secret)
		}
		require.NotContains(t, state.Spec.Template.Annotations, "checksum/configuration")
	})

	t.Run("literal-yaml-configuration", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(projectSource(), "values.yaml"))
		require.NoError(t, err)
		var defaults map[string]any
		require.NoError(t, yaml.Unmarshal(raw, &defaults))
		body, err := yaml.Marshal(defaults["configuration"])
		require.NoError(t, err)
		content := "# Preserve literal YAML and application templates.\n\nstartMessage: '{{ .session.id }}'\n" + string(body) + "\n# End of configuration.\n"
		values, err := yaml.Marshal(map[string]any{"configuration": content})
		require.NoError(t, err)
		objects := renderProject(t, helm, string(values))
		require.Equal(t, content, string(projectConfiguration(t, objects)))
		state := projectObject[*appsv1.StatefulSet](t, objects)
		require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(content))), state.Spec.Template.Annotations["checksum/configuration"])
		var parsed configuration.Configuration
		require.NoError(t, parsed.LoadFromYaml(strings.NewReader(content), ""))
	})

	t.Run("image-digest-and-fullname", func(t *testing.T) {
		digest := "sha256:" + strings.Repeat("a", 64)
		objects := renderProject(t, helm, "fullnameOverride: gateway\nimage:\n  digest: "+digest+"\n")
		state := projectObject[*appsv1.StatefulSet](t, objects)
		require.Equal(t, "gateway", state.Name)
		require.Equal(t, "ghcr.io/engity-com/bifroest@"+digest, state.Spec.Template.Spec.Containers[0].Image)
	})

	t.Run("proxy-ingress-and-unmodified-application-templates", func(t *testing.T) {
		objects := renderProject(t, helm, proxyValues+`
configuration:
  startMessage: '{{ .session.id }}'
  http:
    enabled: true
    domains: [access.example.org]
    addresses: [":8080"]
    upstream:
      mode: reverseProxy
      defaultPrefix: /gateway
      trustedPeers: [10.42.0.0/16]
`)
		ingress := projectObject[*networkingv1.Ingress](t, objects)
		require.Equal(t, "/gateway", ingress.Spec.Rules[0].HTTP.Paths[0].Path)
		require.Equal(t, "access.example.org", ingress.Spec.TLS[0].Hosts[0])
		policy := projectObject[*networkingv1.NetworkPolicy](t, objects)
		require.Len(t, policy.Spec.Ingress[1].From, 1)
		peer := policy.Spec.Ingress[1].From[0]
		require.NotNil(t, peer.NamespaceSelector)
		require.NotNil(t, peer.PodSelector)
		raw := projectConfiguration(t, objects)
		require.Contains(t, string(raw), "{{ .session.id }}")
		var parsed configuration.Configuration
		require.NoError(t, parsed.LoadFromYaml(bytes.NewReader(raw), ""))
	})

	t.Run("external-configmap-and-monitoring-tls", func(t *testing.T) {
		objects := renderProject(t, helm, "configuration: configMap:gateway-config\nmonitoring:\n  scheme: HTTPS\n")
		state := projectObject[*appsv1.StatefulSet](t, objects)
		require.Equal(t, "gateway-config", state.Spec.Template.Spec.Volumes[0].ConfigMap.Name)
		require.Equal(t, corev1.URISchemeHTTPS, state.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Scheme)
		require.NotContains(t, state.Spec.Template.Annotations, "checksum/configuration")
	})

	t.Run("deny-all-ingress", func(t *testing.T) {
		objects := renderProject(t, helm, "service:\n  ssh:\n    enabled: false\nnetworkPolicy:\n  sshPeers: []\n")
		policy := projectObject[*networkingv1.NetworkPolicy](t, objects)
		require.Empty(t, policy.Spec.Ingress)
	})
}

func TestProjectChartPrometheusPodAnnotations(t *testing.T) {
	helm := testHelm(t)
	for _, scheme := range []string{"HTTP", "HTTPS"} {
		t.Run(scheme, func(t *testing.T) {
			objects := renderProject(t, helm, `
configuration: secret:gateway-config
monitoring:
  port: 9191
  scheme: `+scheme+`
  prometheusAnnotations: true
podAnnotations:
  owner: operations
  prometheus.io/port: "overridden"
networkPolicy:
  monitoringPeers:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
`)
			state := projectObject[*appsv1.StatefulSet](t, objects)
			annotations := state.Spec.Template.Annotations
			require.Equal(t, "true", annotations["prometheus.io/scrape"])
			require.Equal(t, "/metrics", annotations["prometheus.io/path"])
			require.Equal(t, "9191", annotations["prometheus.io/port"])
			require.Equal(t, strings.ToLower(scheme), annotations["prometheus.io/scheme"])
			require.Equal(t, "operations", annotations["owner"])
			require.NotContains(t, state.Annotations, "prometheus.io/scrape", "discovery annotations belong on the Pods")
			policy := projectObject[*networkingv1.NetworkPolicy](t, objects)
			rule := policy.Spec.Ingress[len(policy.Spec.Ingress)-1]
			require.EqualValues(t, 9191, rule.Ports[0].Port.IntVal)
			require.Len(t, rule.From, 1)
			require.Equal(t, "monitoring", rule.From[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"])
			require.Equal(t, "prometheus", rule.From[0].PodSelector.MatchLabels["app.kubernetes.io/name"])
		})
	}
}

const proxyValues = `
service:
  http:
    enabled: true
    port: 80
    targetPort: 8080
ingress:
  enabled: true
  host: access.example.org
  path: /gateway
  className: traefik
networkPolicy:
  httpPeers:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: traefik
      podSelector:
        matchLabels:
          app.kubernetes.io/name: traefik
`

func TestProjectChartRejectsUnsafeValuesWithRealHelm(t *testing.T) {
	helm := testHelm(t)
	for name, values := range map[string]string{
		"no-replicas":                      "replicaCount: 0\n",
		"shared-claim":                     "persistence:\n  existingClaim: shared\n",
		"shared-access-mode":               "persistence:\n  accessModes: [ReadWriteMany]\n",
		"empty-secret-reference":           "configuration: 'secret:'\n",
		"empty-configmap-reference":        "configuration: 'configMap:'\n",
		"invalid-secret-name":              "configuration: 'secret:Bad Name'\n",
		"invalid-configmap-name":           "configuration: 'configMap:bad/name'\n",
		"empty-configuration":              "configuration: ''\n",
		"non-mapping-configuration":        "configuration: '- not-a-mapping'\n",
		"invalid-yaml-configuration":       "configuration: 'flows: ['\n",
		"boolean-configuration":            "configuration: false\n",
		"no-monitoring":                    "configuration:\n  monitoring:\n    enabled: false\n",
		"wrong-probe-port":                 "monitoring:\n  port: 1234\n",
		"wrong-probe-scheme":               "monitoring:\n  scheme: HTTPS\n",
		"missing-direct-tls":               "configuration:\n  http:\n    enabled: true\n",
		"invalid-tls-enabled":              "configuration:\n  http:\n    enabled: true\n    tls:\n      enabled: false\n",
		"proxy-without-trust":              "configuration:\n  http:\n    upstream:\n      mode: reverseProxy\n",
		"ingress-without-controller-peers": "ingress:\n  enabled: true\n  host: access.example.org\nconfiguration: secret:external\nservice:\n  http:\n    enabled: true\n",
		"ingress-with-public-backend":      "ingress:\n  enabled: true\n  host: access.example.org\nconfiguration: secret:external\nservice:\n  http:\n    enabled: true\n    type: LoadBalancer\n",
		"blocking-pdb":                     "podDisruptionBudget:\n  enabled: true\n",
		"windows-pods":                     "nodeSelector:\n  kubernetes.io/os: windows\n",
		"empty-policy-peer":                "networkPolicy:\n  httpPeers: [{}]\n",
		"exposed-monitoring":               "service:\n  ssh:\n    targetPort: 9090\n",
		"wrong-ssh-target":                 "service:\n  ssh:\n    targetPort: 22\n",
		"prometheus-without-policy-peers":  "monitoring:\n  prometheusAnnotations: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "values.yaml")
			require.NoError(t, os.WriteFile(file, []byte(values), 0600))
			output, err := exec.CommandContext(t.Context(), helm, "template", "proof", projectSource(), "-f", file).CombinedOutput()
			require.Error(t, err, "%s", output)
		})
	}
}

func testHelm(t *testing.T) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	require.NoError(t, err, "Helm is required for chart tests; use mise run test:go")
	return helm
}

func renderProject(t *testing.T, helm string, values ...string) []runtime.Object {
	t.Helper()
	args := []string{"template", "proof", projectSource(), "--kube-version", "1.32.0"}
	for i, value := range values {
		if value == "" {
			continue
		}
		file := filepath.Join(t.TempDir(), fmt.Sprintf("values-%d.yaml", i))
		require.NoError(t, os.WriteFile(file, []byte(value), 0600))
		args = append(args, "-f", file)
	}
	output, err := exec.CommandContext(t.Context(), helm, args...).CombinedOutput()
	require.NoError(t, err, "%s", output)
	decoder := yaml.NewDecoder(bytes.NewReader(output))
	codec := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict).UniversalDeserializer()
	var result []runtime.Object
	for {
		var node yaml.Node
		if err := decoder.Decode(&node); err == io.EOF {
			break
		} else {
			require.NoError(t, err)
		}
		raw, err := yaml.Marshal(&node)
		require.NoError(t, err)
		if strings.TrimSpace(string(raw)) == "null" {
			continue
		}
		json, err := sigyaml.YAMLToJSONStrict(raw)
		require.NoError(t, err)
		object, _, err := codec.Decode(json, nil, nil)
		require.NoError(t, err, "%s", raw)
		result = append(result, object)
	}
	return result
}

func projectObject[T runtime.Object](t *testing.T, objects []runtime.Object) T {
	t.Helper()
	for _, object := range objects {
		if typed, ok := object.(T); ok {
			return typed
		}
	}
	t.Fatalf("rendered chart has no object of requested type")
	var zero T
	return zero
}

func projectConfiguration(t *testing.T, objects []runtime.Object) []byte {
	t.Helper()
	secret := projectObject[*corev1.Secret](t, objects)
	return secret.Data["configuration.yaml"]
}
