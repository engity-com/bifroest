//go:build e2e && darwin

package e2e_test

import (
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenSSHNativeDarwin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native Darwin credential impersonation requires effective UID 0")
	}
	targetName := os.Getenv("BIFROEST_E2E_TARGET_USER")
	if targetName == "" {
		t.Skip("BIFROEST_E2E_TARGET_USER must name a controlled existing account")
	}
	target, err := osuser.Lookup(targetName)
	if err != nil {
		t.Fatalf("lookup target account %q: %v", targetName, err)
	}
	if target.Uid == "0" {
		t.Fatal("native Darwin SSH test target must not be root")
	}

	f, err := newFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.tempDir, 0755); err != nil {
		t.Fatalf("make fixture accessible to target account: %v", err)
	}
	f.port = "2222"
	if err := f.writeKnownHosts(); err != nil {
		t.Fatal(err)
	}

	configuration := fmt.Sprintf(`startMessage: '{{""}}'
ssh:
  addresses:
    - "127.0.0.1:2222"
  keys:
    hostKeys:
      - %s
    rememberMeNotification: '{{""}}'
  banner: '{{""}}'
session:
  type: fs
  storage: %s
flows:
  - name: native-darwin
    authorization:
      type: local
      authorizedKeys:
        - %s
      password:
        allowed: false
        interactiveAllowed: false
        emptyAllowed: false
      pamService: ""
    environment:
      type: local
      name: %s
      targetAccountPolicy:
        allowAdministrators: true
        allowedNames:
          - %s
`, yamlString(f.hostKey), yamlString(f.sessionStorage), yamlString(f.clientKey+".pub"), yamlString(targetName), yamlString(targetName))
	configurationPath := filepath.Join(f.tempDir, "configuration.yaml")
	if err := os.WriteFile(configurationPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	f.bifroestProc, err = f.launchLoggedProcess("bifroest", nil, f.bifroest, "run", "--configuration="+configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pollProcess(30*time.Second, f.bifroestProc, func() error {
		return probeSSHIdentification(f.host, f.port)
	}); err != nil {
		t.Fatal(err)
	}

	identity := f.ssh(15*time.Second, f.clientKey, targetName, nil, "/usr/bin/id", "-un")
	if identity.err != nil {
		t.Fatalf("native SSH identity failed: %v\nstderr:\n%s", identity.err, identity.stderr)
	}
	if actual := strings.TrimSpace(identity.stdout); actual != targetName {
		t.Fatalf("native SSH identity: got %q, want %q", actual, targetName)
	}

	pty := f.ssh(15*time.Second, f.clientKey, targetName, []string{"-tt"}, "/usr/bin/tty")
	if pty.err != nil {
		t.Fatalf("native SSH PTY failed: %v\nstderr:\n%s", pty.err, pty.stderr)
	}
	if actual := strings.TrimSpace(pty.stdout); !strings.HasPrefix(actual, "/dev/tty") {
		t.Fatalf("native SSH PTY returned unexpected terminal %q", actual)
	}
}
