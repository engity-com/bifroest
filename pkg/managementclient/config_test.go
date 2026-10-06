package managementclient

import (
	"fmt"
	"os"
	"path/filepath"
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
