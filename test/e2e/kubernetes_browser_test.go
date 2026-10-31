//go:build e2e

package e2e_test

import (
	"strings"
	"testing"
	"time"
)

// This starts the existing owned kind/Podman-or-Docker fixture; it never adopts
// the user's kubeconfig context or creates resources in an unrelated cluster.
func TestOpenSSHKubernetesBrowserSharedWorkload(t *testing.T) {
	node := requireSharedWorkloadBrowser(t)
	k, err := newKubernetesExecutionFixture(t, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s owned-cluster=%s namespace=%s", k.runtimeCLI, k.clusterName, k.namespace)
	exerciseSharedBrowserWorkload(t, k.fixture, node, "kubernetes", func(t *testing.T) (string, string) {
		if err := k.waitForEnvironmentPod(); err != nil {
			t.Fatal(err)
		}
		pods, err := k.podNames()
		if err != nil || len(pods) != 1 || pods[0] != k.environmentPod {
			t.Fatalf("shared Pod inventory: %v %v", pods, err)
		}
		identity := k.kubectl(10*time.Second, "get", "pod", k.environmentPod, "-n", k.namespace, "-o", "jsonpath={.metadata.uid}")
		marker := k.podExec(10*time.Second, "/bin/cat", sharedBrowserMarker)
		if identity.err != nil || strings.TrimSpace(identity.stdout) == "" || marker.err != nil {
			t.Fatalf("inspect shared Pod: identity=%v marker=%v", identity.err, marker.err)
		}
		return strings.TrimSpace(identity.stdout), marker.stdout
	})
}
