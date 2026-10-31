//go:build e2e

package e2e_test

import (
	"strings"
	"testing"
	"time"
)

func TestOpenSSHDockerBrowserSharedWorkload(t *testing.T) {
	node := requireSharedWorkloadBrowser(t)
	f, err := newDockerEnvironmentExecutionFixture(t, true, true)
	if err != nil {
		t.Fatal(err)
	} // An explicitly requested browser proof cannot pass by skipping a missing runtime.
	t.Logf("runtime=%s host=%s network=%s", f.runtimeCLI, f.runtimeHost, f.networkID)
	exerciseSharedBrowserWorkload(t, f, node, "docker", func(t *testing.T) (string, string) {
		if err := f.waitForEnvironmentContainer(); err != nil {
			t.Fatal(err)
		}
		ids, err := f.containerIDs()
		if err != nil || len(ids) != 1 || ids[0] != f.containerID {
			t.Fatalf("shared Docker container inventory: %v %v", ids, err)
		}
		identity := f.runtime(10*time.Second, "container", "inspect", "--format", "{{.Id}}", f.containerID)
		marker := f.runtime(10*time.Second, "exec", f.containerID, "/bin/cat", sharedBrowserMarker)
		fullID := strings.TrimSpace(identity.stdout)
		// ps --quiet uses a short ID; inspect is the independent full identity.
		if identity.err != nil || len(fullID) != 64 || !strings.HasPrefix(fullID, f.containerID) || marker.err != nil {
			t.Fatalf("inspect shared Docker container: listed=%q inspected=%q identity=%v marker=%v", f.containerID, fullID, identity.err, marker.err)
		}
		return fullID, marker.stdout
	})
}
