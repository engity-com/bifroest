package management

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/require"
)

func TestSSHConfigIncludeCustomManagementProperties(t *testing.T) {
	directory := t.TempDir()
	key := filepath.Join(directory, "decryption.key")
	hosts := filepath.Join(directory, "known_hosts")
	require.NoError(t, os.WriteFile(hosts, []byte("test\n"), 0600))
	include := filepath.Join(directory, "included-hosts")
	conf := fmt.Sprintf("Host admin-alias\n HostName bifroest.example.org\n User manager\n Port 2222\n UserKnownHostsFile %s\n X-RecordingPrivateKey %s\n X-AuditPrivateKey %s\n X-ExpectedProducerId %s\n X-SSHAgent pageant\n", hosts, key, key, "abc123")
	require.NoError(t, os.WriteFile(include, []byte(conf), 0600))
	main := filepath.Join(directory, "config")
	require.NoError(t, os.WriteFile(main, []byte("IgnoreUnknown X-*\nInclude "+include+"\n"), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return main })
	ssh_config.DefaultUserSettings = settings
	defer func() { ssh_config.DefaultUserSettings = previous }()
	target := Target{Host: "admin-alias", Port: 22}
	actual, err := resolve(target)
	require.NoError(t, err)
	require.Equal(t, "bifroest.example.org", actual.host)
	require.Equal(t, "manager", actual.user)
	require.Equal(t, uint16(2222), actual.port)
	require.Equal(t, "pageant", actual.agentPath)
	require.Equal(t, []string{hosts}, actual.knownHosts)
	private, err := RecordingPrivateKey(target)
	require.NoError(t, err)
	require.Equal(t, key, private)
	private, err = AuditPrivateKey(target)
	require.NoError(t, err)
	require.Equal(t, key, private)
	producer, err := ExpectedRecordingProducerID(target)
	require.NoError(t, err)
	require.Equal(t, "abc123", producer)
}

func TestSSHConfigQuotedPaths(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "paths with spaces")
	require.NoError(t, os.Mkdir(directory, 0700))
	key := filepath.ToSlash(filepath.Join(directory, "identity"))
	hosts := filepath.ToSlash(filepath.Join(directory, "known_hosts"))
	require.NoError(t, os.WriteFile(hosts, []byte("test\n"), 0600))
	configPath := filepath.Join(t.TempDir(), "config")
	config := fmt.Sprintf("Host quoted\n HostName bifroest.example.org\n User manager\n IdentityFile %q\n IdentityAgent none\n UserKnownHostsFile %q\n X-RecordingPrivateKey %q\n X-AuditPrivateKey %q\n", key, hosts, key, key)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	target := Target{Host: "quoted"}
	actual, err := resolve(target)
	require.NoError(t, err)
	require.Equal(t, []string{key}, actual.identities)
	require.Equal(t, []string{hosts}, actual.knownHosts)
	recordingKey, err := RecordingPrivateKey(target)
	require.NoError(t, err)
	require.Equal(t, key, recordingKey)
	auditKey, err := AuditPrivateKey(target)
	require.NoError(t, err)
	require.Equal(t, key, auditKey)
}

func TestMissingQuotedKnownHostsPathDoesNotTrustFragments(t *testing.T) {
	directory := t.TempDir()
	fragment := filepath.ToSlash(filepath.Join(directory, "trusted-fragment"))
	require.NoError(t, os.WriteFile(fragment, []byte("unrelated host trust file\n"), 0600))
	configPath := filepath.Join(directory, "config")
	config := fmt.Sprintf("Host missing-quoted\n HostName bifroest.example.org\n User manager\n UserKnownHostsFile %q\n", fragment+" missing")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	_, err := resolve(Target{Host: "missing-quoted"})
	require.ErrorContains(t, err, "no SSH known_hosts file")
}

func TestSSHConfigUsesDefaultKnownHostsFile(t *testing.T) {
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	knownHosts := filepath.Join(home, ".ssh", "known_hosts")
	require.NoError(t, os.Mkdir(filepath.Dir(knownHosts), 0700))
	require.NoError(t, os.WriteFile(knownHosts, []byte("test\n"), 0600))
	configPath := filepath.Join(home, "config")
	require.NoError(t, os.WriteFile(configPath, []byte("Host default-hosts\n HostName bifroest.example.org\n User manager\n"), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	actual, err := resolve(Target{Host: "default-hosts"})
	require.NoError(t, err)
	require.Equal(t, []string{knownHosts}, actual.knownHosts)
}

func TestSSHConfigDisabledKnownHostsDoesNotReadWorkingDirectoryFile(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	require.NoError(t, os.WriteFile("none", []byte("unrelated host trust file\n"), 0600))
	configPath := filepath.Join(directory, "config")
	require.NoError(t, os.WriteFile(configPath, []byte("Host disabled-hosts\n HostName bifroest.example.org\n User manager\n UserKnownHostsFile none\n"), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	_, err := resolve(Target{Host: "disabled-hosts"})
	require.ErrorContains(t, err, "requires a trusted UserKnownHostsFile")
}

func TestSelectedSSHConfigurationIsIsolatedFromUnsupportedMatchFinal(t *testing.T) {
	directory := t.TempDir()
	unsupported := filepath.Join(directory, "system-config")
	require.NoError(t, os.WriteFile(unsupported, []byte("Match final\n UserKnownHostsFile unsafe-trust\n"), 0600))
	previous := ssh_config.DefaultUserSettings
	defaults := &ssh_config.UserSettings{}
	defaults.ConfigFinder(func() string { return unsupported })
	ssh_config.DefaultUserSettings = defaults
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	_, err := resolve(Target{Host: "selected"})
	require.ErrorContains(t, err, "unsupported Match criterion")
	require.ErrorContains(t, err, "--sshConfig")
	hosts := filepath.ToSlash(filepath.Join(directory, "known-hosts"))
	require.NoError(t, os.WriteFile(hosts, []byte("selected host trust\n"), 0600))
	include := filepath.Join(directory, "included")
	key := filepath.ToSlash(filepath.Join(directory, "recipient"))
	raw := fmt.Sprintf("Host selected\n HostName selected.example.org\n User manager\n Port 2222\n IdentityAgent none\n IdentityFile selected-login\n UserKnownHostsFile %q\n X-AuditPrivateKey %q\n X-RecordingPrivateKey %q\n X-ExpectedProducerId selected-producer\n", hosts, key, key)
	require.NoError(t, os.WriteFile(include, []byte(raw), 0600))
	selected := filepath.Join(directory, "selected.conf")
	require.NoError(t, os.WriteFile(selected, []byte("IgnoreUnknown X-*\nInclude "+filepath.ToSlash(include)+"\n"), 0600))
	target := Target{Host: "selected", SSHConfigFile: selected}
	actual, err := resolve(target)
	require.NoError(t, err)
	require.Equal(t, "selected.example.org", actual.host)
	require.Equal(t, "manager", actual.user)
	require.Equal(t, uint16(2222), actual.port)
	require.Equal(t, []string{"selected-login"}, actual.identities)
	require.Equal(t, []string{hosts}, actual.knownHosts)
	auditKey, err := AuditPrivateKey(target)
	require.NoError(t, err)
	require.Equal(t, key, auditKey)
	recordingKey, err := RecordingPrivateKey(target)
	require.NoError(t, err)
	require.Equal(t, key, recordingKey)
	producer, err := ExpectedRecordingProducerID(target)
	require.NoError(t, err)
	require.Equal(t, "selected-producer", producer)
}

func TestSelectedSSHConfigurationNeverFallsBackAfterErrors(t *testing.T) {
	directory := t.TempDir()
	hosts := filepath.Join(directory, "known-hosts")
	require.NoError(t, os.WriteFile(hosts, []byte("default host trust\n"), 0600))
	defaultPath := filepath.Join(directory, "working-default.conf")
	require.NoError(t, os.WriteFile(defaultPath, []byte(fmt.Sprintf("Host selected\n HostName default.example.org\n User manager\n UserKnownHostsFile %q\n", filepath.ToSlash(hosts))), 0600))
	previous := ssh_config.DefaultUserSettings
	defaults := &ssh_config.UserSettings{}
	defaults.ConfigFinder(func() string { return defaultPath })
	ssh_config.DefaultUserSettings = defaults
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	_, err := resolve(Target{Host: "selected"})
	require.NoError(t, err, "the ordinary configuration would work if it were incorrectly used as a fallback")
	unsupported := filepath.Join(directory, "unsupported.conf")
	require.NoError(t, os.WriteFile(unsupported, []byte("Match final\n UserKnownHostsFile unsafe-trust\n"), 0600))
	for _, path := range []string{unsupported, filepath.Join(directory, "missing.conf")} {
		target := Target{Host: "selected", SSHConfigFile: path}
		_, err := resolve(target)
		require.ErrorContains(t, err, "cannot read selected SSH configuration")
		_, err = AuditPrivateKey(target)
		require.ErrorContains(t, err, "cannot read selected SSH configuration")
		_, err = RecordingPrivateKey(target)
		require.ErrorContains(t, err, "cannot read selected SSH configuration")
		_, err = ExpectedRecordingProducerID(target)
		require.ErrorContains(t, err, "cannot read selected SSH configuration")
	}
}

func TestSelectedSSHConfigurationIsProtectedFromOutputs(t *testing.T) {
	directory := t.TempDir()
	hosts := filepath.ToSlash(filepath.Join(directory, "known-hosts"))
	require.NoError(t, os.WriteFile(hosts, []byte("host trust\n"), 0600))
	path := filepath.Join(directory, "selected.conf")
	raw := []byte(fmt.Sprintf("Host selected\n HostName selected.example.org\n User admin\n UserKnownHostsFile %q\n", hosts))
	require.NoError(t, os.WriteFile(path, raw, 0600))
	target := Target{Host: "selected", SSHConfigFile: path}
	for _, alias := range []bool{false, true} {
		outputPath := path
		if alias {
			outputPath = filepath.Join(t.TempDir(), "config-alias")
			if err := os.Link(path, outputPath); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		}
		require.ErrorContains(t, target.EnsureOutputSafe(t.Context(), outputPath, nil), "must not replace SSH client configuration")
		output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_APPEND, 0)
		require.NoError(t, err)
		require.ErrorContains(t, target.EnsureOutputSafe(t.Context(), "-", output), "must not replace SSH client configuration")
		require.NoError(t, output.Close())
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, raw, content)
	}
}
