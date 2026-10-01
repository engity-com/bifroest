//go:build e2e && darwin

package e2e_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	bfuser "github.com/engity-com/bifroest/pkg/user"
)

const (
	darwinPrivilegedTestMarker     = "BIFROEST_DARWIN_PRIVILEGED_TEST"
	darwinServiceTestBinary        = "BIFROEST_DARWIN_SERVICE_TEST_BINARY"
	darwinServiceLabel             = "com.engity.bifroest"
	darwinServicePlist             = "/Library/LaunchDaemons/" + darwinServiceLabel + ".plist"
	darwinServiceBinary            = "/Library/PrivilegedHelperTools/" + darwinServiceLabel
	darwinServiceLock              = "/Library/PrivilegedHelperTools/." + darwinServiceLabel + ".lock"
	darwinServiceStateDirectory    = "/Library/Application Support/Engity/Bifroest"
	darwinServiceConfiguration     = darwinServiceStateDirectory + "/configuration.yaml"
	darwinServiceLogDirectory      = "/Library/Logs/Engity/Bifroest"
	darwinServiceLaunchTarget      = "system/" + darwinServiceLabel
	darwinServiceTestWaitAttempts  = 60
	darwinServiceTestRestartPeriod = 11 * time.Second
)

func TestOpenSSHLocalNative(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatalf("native Darwin test requires amd64 or arm64, got %s", runtime.GOARCH)
	}
	if expected := os.Getenv("BIFROEST_E2E_EXPECTED_ARCH"); expected != "" && expected != runtime.GOARCH {
		t.Fatalf("native Darwin test runs on %s, expected %s", runtime.GOARCH, expected)
	}
	if !runDarwinTestAsRoot(t) {
		return
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

func TestDarwinLocalAccountLifecycle(t *testing.T) {
	if !runDarwinTestAsRoot(t) {
		return
	}
	suffix := strconv.FormatInt(time.Now().UnixNano()%1_000_000_000, 10)
	accountName := "bifroest-e2e-" + suffix
	primaryGroupName := accountName + "-primary"
	extraGroupName := accountName + "-extra"
	home := filepath.Join("/Users", accountName)
	updatedHome := home + "-updated"
	repository := &bfuser.DarwinRepository{}
	if err := repository.Init(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repository.Close() })
	cleanup := func() {
		no := false
		yes := true
		if account, err := repository.LookupByName(context.Background(), accountName); err == nil {
			_ = repository.DeleteByIdentity(context.Background(), account.Uid, accountName, account.HomeDir, &bfuser.DeleteOpts{HomeDir: &yes, KillProcesses: &yes})
		}
		_ = repository.DeleteGroupByName(context.Background(), extraGroupName, &bfuser.DeleteOpts{HomeDir: &no, KillProcesses: &no})
		_ = repository.DeleteGroupByName(context.Background(), primaryGroupName, &bfuser.DeleteOpts{HomeDir: &no, KillProcesses: &no})
		_ = exec.Command("/usr/bin/dscl", "/Local/Default", "-delete", "/Users/"+accountName).Run()
		_ = exec.Command("/usr/bin/dscl", "/Local/Default", "-delete", "/Groups/"+extraGroupName).Run()
		_ = exec.Command("/usr/bin/dscl", "/Local/Default", "-delete", "/Groups/"+primaryGroupName).Run()
		_ = os.RemoveAll(home)
		_ = os.RemoveAll(updatedHome)
	}
	t.Cleanup(cleanup)
	if _, err := osuser.Lookup(accountName); err == nil {
		t.Fatalf("refusing to use existing Darwin account %q", accountName)
	}
	for _, name := range []string{primaryGroupName, extraGroupName} {
		if _, err := osuser.LookupGroup(name); err == nil {
			t.Fatalf("refusing to use existing Darwin group %q", name)
		}
	}
	for _, path := range []string{home, updatedHome} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("refusing to use existing Darwin home %q", path)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}

	yes := true
	requirement := &bfuser.Requirement{
		Name:        accountName,
		DisplayName: "Bifroest Darwin E2E",
		Group:       bfuser.GroupRequirement{Name: primaryGroupName},
		Groups:      bfuser.GroupRequirements{{Name: extraGroupName}},
		Shell:       "/bin/zsh",
		HomeDir:     home,
	}
	account, result, err := repository.Ensure(t.Context(), requirement, &bfuser.EnsureOpts{CreateAllowed: &yes, ModifyAllowed: &yes, HomeDir: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if result != bfuser.EnsureResultCreated {
		t.Fatalf("created account returned result %v", result)
	}
	darwinRequireLifecycleAccount(t, account, requirement)

	f, err := newFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.tempDir, 0755); err != nil {
		t.Fatal(err)
	}
	f.port = "2223"
	if err := f.writeKnownHosts(); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf(`startMessage: '{{""}}'
ssh:
  addresses:
    - "127.0.0.1:2223"
  keys:
    hostKeys:
      - %s
    rememberMeNotification: '{{""}}'
  banner: '{{""}}'
session:
  type: fs
  storage: %s
flows:
  - name: darwin-account-lifecycle
    authorization:
      type: simple
      entries:
        - name: e2e
          authorizedKeysFile: %s
    environment:
      type: local
      name: %s
      targetAccountPolicy:
        allowedNames:
          - %s
`, yamlString(f.hostKey), yamlString(f.sessionStorage), yamlString(f.clientKey+".pub"), yamlString(accountName), yamlString(accountName))
	configurationPath := filepath.Join(f.tempDir, "darwin-account-lifecycle.yaml")
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
	identity := f.ssh(15*time.Second, f.clientKey, "e2e", nil, "/usr/bin/id", "-un")
	if identity.err != nil || strings.TrimSpace(identity.stdout) != accountName {
		t.Fatalf("managed Darwin SSH identity failed: %v\nstdout:\n%s\nstderr:\n%s", identity.err, identity.stdout, identity.stderr)
	}
	pty := f.ssh(15*time.Second, f.clientKey, "e2e", []string{"-tt"}, "/usr/bin/tty")
	if pty.err != nil || !strings.HasPrefix(strings.TrimSpace(pty.stdout), "/dev/tty") {
		t.Fatalf("managed Darwin SSH PTY failed: %v\nstdout:\n%s\nstderr:\n%s", pty.err, pty.stdout, pty.stderr)
	}

	requirement.DisplayName = "Bifroest Darwin E2E Updated"
	requirement.Shell = "/bin/bash"
	requirement.HomeDir = updatedHome
	account, result, err = repository.Ensure(t.Context(), requirement, &bfuser.EnsureOpts{CreateAllowed: &yes, ModifyAllowed: &yes, HomeDir: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if result != bfuser.EnsureResultModified {
		t.Fatalf("updated account returned result %v", result)
	}
	darwinRequireLifecycleAccount(t, account, requirement)
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("old Darwin home still exists after move: %v", err)
	}

	sleeper := exec.Command("/usr/bin/su", "-m", accountName, "-c", "exec /bin/sleep 60")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- sleeper.Wait() }()
	t.Cleanup(func() {
		if sleeper.Process != nil {
			_ = sleeper.Process.Kill()
		}
	})
	time.Sleep(250 * time.Millisecond)
	if err := repository.KillProcessesByIdentity(t.Context(), account.Uid, accountName); err != nil {
		t.Fatal(err)
	}
	select {
	case <-processDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Darwin account process was not terminated")
	}

	if err := repository.DeleteByIdentity(t.Context(), account.Uid, accountName, updatedHome, &bfuser.DeleteOpts{HomeDir: &yes, KillProcesses: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := osuser.Lookup(accountName); err == nil {
		t.Fatal("Darwin account still resolves after deletion")
	}
	if _, err := os.Lstat(updatedHome); !os.IsNotExist(err) {
		t.Fatalf("Darwin home still exists after deletion: %v", err)
	}
	if err := repository.DeleteGroupByName(t.Context(), extraGroupName, nil); err != nil {
		t.Fatal(err)
	}
	if err := repository.DeleteGroupByName(t.Context(), primaryGroupName, nil); err != nil {
		t.Fatal(err)
	}
}

func darwinRequireLifecycleAccount(t *testing.T, actual *bfuser.User, requirement *bfuser.Requirement) {
	t.Helper()
	if actual.Name != requirement.Name || actual.DisplayName != requirement.DisplayName || actual.Shell != requirement.Shell || actual.HomeDir != requirement.HomeDir {
		t.Fatalf("Darwin account does not match requirement: actual=%+v requirement=%+v", actual, requirement)
	}
	if actual.Group.Name != requirement.Group.Name || len(actual.Groups) != len(requirement.Groups) || actual.Groups[0].Name != requirement.Groups[0].Name {
		t.Fatalf("Darwin account groups do not match requirement: %+v", actual)
	}
	info, err := os.Stat(actual.HomeDir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(actual.Uid) || stat.Gid != uint32(actual.Group.Gid) {
		t.Fatalf("Darwin home has owner %v, expected %d:%d", info.Sys(), actual.Uid, actual.Group.Gid)
	}
}

func TestDarwinLaunchDaemon(t *testing.T) {
	if os.Geteuid() != 0 {
		f, err := newFixture(t)
		if err != nil {
			t.Fatal(err)
		}
		current, err := osuser.Current()
		if err != nil {
			t.Fatal(err)
		}
		runDarwinServiceTestAsRoot(t, f.bifroest, current.Username)
		return
	}
	sourceBinary := os.Getenv(darwinServiceTestBinary)
	if sourceBinary == "" {
		t.Fatal("missing source binary for privileged service test")
	}
	runnerUser := os.Getenv("BIFROEST_E2E_TARGET_USER")
	if runnerUser == "" {
		t.Fatal("missing invoking user for privileged service test")
	}
	if expected := os.Getenv("BIFROEST_E2E_EXPECTED_ARCH"); expected != "" && expected != runtime.GOARCH {
		t.Fatalf("native Darwin service test runs on %s, expected %s", runtime.GOARCH, expected)
	}
	for _, path := range []string{darwinServicePlist, darwinServiceBinary, darwinServiceStateDirectory, darwinServiceLogDirectory} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("clean-host LaunchDaemon test refuses to replace existing path: %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if connection, err := net.DialTimeout("tcp", "127.0.0.1:22", time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("clean-host LaunchDaemon test requires port 22 to be unused")
	}
	repositoryRoot, err := findRepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			diagnostics := filepath.Join(repositoryRoot, "var/e2e/darwin-service-"+runtime.GOARCH)
			_ = os.MkdirAll(diagnostics, 0755)
			for _, name := range []string{"stdout.log", "stderr.log"} {
				if content, err := os.ReadFile(filepath.Join(darwinServiceLogDirectory, name)); err == nil {
					_ = os.WriteFile(filepath.Join(diagnostics, name), content, 0644)
				}
			}
		}
		_, _ = runDarwinServiceTestCommand(sourceBinary, "service", "remove")
		_, _ = runDarwinServiceTestCommand("/bin/launchctl", "bootout", darwinServiceLaunchTarget)
		_ = os.Remove(darwinServicePlist)
		_ = os.Remove(darwinServiceBinary)
		_ = os.Remove(darwinServiceLock)
		_ = os.RemoveAll(darwinServiceStateDirectory)
		_ = os.RemoveAll(darwinServiceLogDirectory)
	})
	configurationTemplate, err := os.ReadFile(filepath.Join(repositoryRoot, "contrib/configurations/native-macos.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(configurationTemplate), "- alice") != 1 {
		t.Fatal("native macOS configuration does not contain exactly one example account")
	}
	configuration := strings.Replace(string(configurationTemplate), "- alice", "- "+runnerUser, 1)
	if err := os.MkdirAll(darwinServiceStateDirectory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(darwinServiceStateDirectory, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(darwinServiceStateDirectory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(darwinServiceLogDirectory, 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(darwinServiceLogDirectory, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(darwinServiceLogDirectory, 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(darwinServiceConfiguration, []byte(configuration), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(darwinServiceConfiguration, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(darwinServiceConfiguration, 0640); err != nil {
		t.Fatal(err)
	}
	stateModeBefore := darwinServiceTestFileMode(t, darwinServiceStateDirectory)
	logModeBefore := darwinServiceTestFileMode(t, darwinServiceLogDirectory)
	darwinServiceTestTouch(t, filepath.Join(darwinServiceStateDirectory, "preserve-on-upgrade"))
	darwinServiceTestTouch(t, filepath.Join(darwinServiceLogDirectory, "preserve-on-upgrade"))
	darwinServiceTestRun(t, sourceBinary, "service", "install")
	darwinServiceTestWait(t)
	firstPid := darwinServiceTestPid(t)
	if user := strings.TrimSpace(darwinServiceTestRun(t, "/bin/ps", "-o", "user=", "-p", strconv.Itoa(firstPid))); user != "root" {
		t.Fatalf("LaunchDaemon runs as %q instead of root", user)
	}
	cwd := darwinServiceTestRun(t, "/usr/sbin/lsof", "-a", "-p", strconv.Itoa(firstPid), "-d", "cwd", "-Fn")
	if !strings.Contains(cwd, "n"+darwinServiceStateDirectory) {
		t.Fatalf("LaunchDaemon working directory is not %s: %s", darwinServiceStateDirectory, cwd)
	}
	darwinServiceTestRequireOwnerMode(t, darwinServicePlist, 0, 0, 0644)
	darwinServiceTestRequireOwnerMode(t, darwinServiceBinary, 0, 0, 0755)
	darwinServiceTestRequireOwnerMode(t, darwinServiceConfiguration, 0, 0, 0640)
	for _, filename := range []string{
		filepath.Join(darwinServiceLogDirectory, "stdout.log"),
		filepath.Join(darwinServiceLogDirectory, "stderr.log"),
	} {
		if _, err := os.Stat(filename); err != nil {
			t.Fatal(err)
		}
	}

	if err := syscall.Kill(firstPid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	darwinServiceTestWait(t)
	if secondPid := darwinServiceTestPid(t); secondPid == firstPid {
		t.Fatalf("LaunchDaemon did not restart after SIGKILL: %d", firstPid)
	}

	sourceDigest := darwinServiceTestDigest(t, sourceBinary)
	plistDigest := darwinServiceTestDigest(t, darwinServicePlist)
	brokenBinary := filepath.Join(t.TempDir(), "broken-binary")
	if err := os.WriteFile(brokenBinary, []byte("broken"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(brokenBinary, darwinServiceBinary); err != nil {
		t.Fatal(err)
	}
	plist, err := os.OpenFile(darwinServicePlist, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plist.WriteString("\n<!-- broken -->\n"); err != nil {
		_ = plist.Close()
		t.Fatal(err)
	}
	if err := plist.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(darwinServicePlist, 0600); err != nil {
		t.Fatal(err)
	}
	darwinServiceTestRun(t, sourceBinary, "service", "install")
	darwinServiceTestWait(t)
	if actual := darwinServiceTestDigest(t, darwinServiceBinary); actual != sourceDigest {
		t.Fatalf("installed binary digest is %s instead of %s", actual, sourceDigest)
	}
	if actual := darwinServiceTestDigest(t, darwinServicePlist); actual != plistDigest {
		t.Fatalf("installed plist digest is %s instead of %s", actual, plistDigest)
	}
	if actual := darwinServiceTestFileMode(t, darwinServiceStateDirectory); actual != stateModeBefore {
		t.Fatalf("state directory mode changed from %o to %o", stateModeBefore, actual)
	}
	if actual := darwinServiceTestFileMode(t, darwinServiceLogDirectory); actual != logModeBefore {
		t.Fatalf("log directory mode changed from %o to %o", logModeBefore, actual)
	}
	for _, filename := range []string{
		filepath.Join(darwinServiceStateDirectory, "preserve-on-upgrade"),
		filepath.Join(darwinServiceLogDirectory, "preserve-on-upgrade"),
	} {
		if _, err := os.Stat(filename); err != nil {
			t.Fatal(err)
		}
	}
	darwinServiceTestTouch(t, filepath.Join(darwinServiceStateDirectory, "preserve-on-remove"))
	darwinServiceTestTouch(t, filepath.Join(darwinServiceLogDirectory, "preserve-on-remove"))

	darwinServiceTestRun(t, darwinServiceBinary, "service", "stop")
	if darwinServiceTestLoaded() {
		t.Fatal("LaunchDaemon is still loaded after stop")
	}
	time.Sleep(darwinServiceTestRestartPeriod)
	if darwinServiceTestLoaded() {
		t.Fatal("LaunchDaemon restarted after stop")
	}
	darwinServiceTestRun(t, darwinServiceBinary, "service", "start")
	darwinServiceTestWait(t)
	darwinServiceTestRun(t, darwinServiceBinary, "service", "remove")
	for _, filename := range []string{darwinServicePlist, darwinServiceBinary} {
		if _, err := os.Lstat(filename); err == nil {
			t.Fatalf("path remains after service remove: %s", filename)
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	for _, filename := range []string{
		darwinServiceConfiguration,
		filepath.Join(darwinServiceStateDirectory, "preserve-on-remove"),
		filepath.Join(darwinServiceLogDirectory, "preserve-on-remove"),
	} {
		if _, err := os.Stat(filename); err != nil {
			t.Fatal(err)
		}
	}
}

func runDarwinServiceTestAsRoot(t *testing.T, binary, user string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sudo", "-n", "env",
		"PATH="+os.Getenv("PATH"),
		"HOME="+os.Getenv("HOME"),
		"BIFROEST_E2E_TARGET_USER="+user,
		"BIFROEST_E2E_EXPECTED_ARCH="+os.Getenv("BIFROEST_E2E_EXPECTED_ARCH"),
		darwinServiceTestBinary+"="+binary,
		executable,
		"-test.run=^"+regexp.QuoteMeta(t.Name())+"$",
		"-test.v",
		"-test.timeout=25m",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		if os.Getenv("CI") == "" {
			t.Skipf("passwordless sudo is unavailable: %v", err)
		}
		t.Fatalf("privileged service test failed: %v\n%s", err, output)
	}
	t.Logf("privileged service test output:\n%s", output)
}

func darwinServiceTestRun(t *testing.T, executable string, args ...string) string {
	t.Helper()
	output, err := runDarwinServiceTestCommand(executable, args...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func runDarwinServiceTestCommand(executable string, args ...string) (string, error) {
	output, err := exec.Command(executable, args...).CombinedOutput()
	plain := strings.TrimSpace(string(output))
	if err != nil {
		return plain, fmt.Errorf("%s %s failed: %w: %s", executable, strings.Join(args, " "), err, plain)
	}
	return plain, nil
}

func darwinServiceTestWait(t *testing.T) {
	t.Helper()
	for range darwinServiceTestWaitAttempts {
		if darwinServiceTestLoaded() {
			if err := probeSSHIdentification("127.0.0.1", "22"); err == nil {
				return
			}
		}
		time.Sleep(time.Second)
	}
	output, _ := runDarwinServiceTestCommand("/bin/launchctl", "print", darwinServiceLaunchTarget)
	t.Fatalf("LaunchDaemon did not become ready:\n%s", output)
}

func darwinServiceTestLoaded() bool {
	return exec.Command("/bin/launchctl", "print", darwinServiceLaunchTarget).Run() == nil
}

func darwinServiceTestPid(t *testing.T) int {
	t.Helper()
	output := darwinServiceTestRun(t, "/bin/launchctl", "kickstart", "-p", darwinServiceLaunchTarget)
	pid, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid LaunchDaemon PID %q: %v", output, err)
	}
	return pid
}

func darwinServiceTestRequireOwnerMode(t *testing.T, filename string, uid, gid uint32, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("cannot inspect ownership of %s", filename)
	}
	if stat.Uid != uid || stat.Gid != gid || info.Mode().Perm() != mode {
		t.Fatalf("%s has owner %d:%d mode %o, expected %d:%d mode %o", filename, stat.Uid, stat.Gid, info.Mode().Perm(), uid, gid, mode)
	}
}

func darwinServiceTestFileMode(t *testing.T, filename string) os.FileMode {
	t.Helper()
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func darwinServiceTestDigest(t *testing.T, filename string) string {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(content))
}

func darwinServiceTestTouch(t *testing.T, filename string) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func runDarwinTestAsRoot(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return true
	}
	if os.Getenv(darwinPrivilegedTestMarker) == "1" {
		t.Fatal("sudo did not provide effective UID 0")
	}
	current, err := osuser.Current()
	if err != nil {
		t.Fatalf("resolve current account: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	cache := filepath.Join(os.TempDir(), "bifroest-root-go-cache")
	command := exec.Command("sudo", "-n", "env",
		"PATH="+os.Getenv("PATH"),
		"HOME="+os.Getenv("HOME"),
		"GOCACHE="+cache,
		darwinPrivilegedTestMarker+"=1",
		"BIFROEST_E2E_TARGET_USER="+current.Username,
		executable,
		"-test.run=^"+regexp.QuoteMeta(t.Name())+"$",
		"-test.v",
		"-test.timeout=15m",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		if os.Getenv("CI") == "" {
			t.Skipf("passwordless sudo is unavailable: %v", err)
		}
		t.Fatalf("privileged test failed: %v\n%s", err, output)
	}
	t.Logf("privileged test output:\n%s", output)
	return false
}
