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
