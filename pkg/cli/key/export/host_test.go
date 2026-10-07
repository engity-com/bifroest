package export

import (
	"bytes"
	"fmt"
	goos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestKeyExportHostCreatesExplicitKeyAndUsesNoClobber(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "identity")

	hostKeyFile := filepath.Join(directory, "host-key")
	opts := hostOpts{identityFile: identityFile, Address: "host.example", output: hostKeyFile}
	require.NoError(t, handleHost(&opts, &bytes.Buffer{}))
	require.FileExists(t, identityFile)
	require.Error(t, handleHost(&opts, &bytes.Buffer{}))
}

func TestKeyExportHostDoesNotReplacePrivateKeyWithForce(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "identity")
	opts := hostOpts{identityFile: identityFile, Address: "host.example", output: identityFile, Force: true}

	err := handleHost(&opts, &bytes.Buffer{})
	require.ErrorContains(t, err, "must not replace private key")
	privateRaw, readErr := goos.ReadFile(identityFile)
	require.NoError(t, readErr)
	_, parseErr := ssh.ParsePrivateKey(privateRaw)
	require.NoError(t, parseErr)
}

func TestKeyExportHostUsesAndCreatesAllConfiguredHostKeys(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first")
	second := filepath.Join(directory, "second")
	configurationFile := filepath.Join(directory, "configuration.yaml")
	raw := fmt.Sprintf(`ssh:
  keys:
    hostKeys:
      - %s
      - %s
flows:
  - name: test
    authorization:
      type: simple
    environment:
      type: dummy
`, first, second)
	require.NoError(t, goos.WriteFile(configurationFile, []byte(raw), 0600))

	var stdout bytes.Buffer
	opts := hostOpts{configuration: configurationFile, Address: "host.example", output: "-"}
	require.NoError(t, handleHost(&opts, &stdout))
	require.FileExists(t, first)
	require.FileExists(t, second)

	remaining := stdout.Bytes()
	for range 2 {
		_, hosts, _, _, rest, err := ssh.ParseKnownHosts(remaining)
		require.NoError(t, err)
		require.Equal(t, []string{"host.example"}, hosts)
		remaining = rest
	}
	require.Empty(t, bytes.TrimSpace(remaining))

	opts.output = first
	opts.Force = true
	require.ErrorContains(t, handleHost(&opts, &bytes.Buffer{}), "must not replace private key")
}

func TestKeyExportHostRejectsConfigurationWithIdentityFile(t *testing.T) {
	err := handleHost(&hostOpts{
		configuration: "configuration.yaml",
		identityFile:  "identity",
		Address:       "host.example",
		output:        "-",
	}, &bytes.Buffer{})
	require.ErrorContains(t, err, "cannot be combined")
}

func TestKeyExportHostProtectsRenderedPrivateKeyPath(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "host-key")
	configurationFile := filepath.Join(directory, "configuration.yaml")
	raw := fmt.Sprintf(`ssh:
  keys:
    hostKeys:
      - '{{if .}}%s{{end}}'
flows:
  - name: test
    authorization:
      type: simple
    environment:
      type: dummy
`, identityFile)
	require.NoError(t, goos.WriteFile(configurationFile, []byte(raw), 0600))

	err := handleHost(&hostOpts{
		configuration: configurationFile,
		Address:       "host.example",
		output:        identityFile,
		Force:         true,
	}, &bytes.Buffer{})
	require.ErrorContains(t, err, "must not replace private key")
	privateRaw, readErr := goos.ReadFile(identityFile)
	require.NoError(t, readErr)
	_, parseErr := ssh.ParsePrivateKey(privateRaw)
	require.NoError(t, parseErr)
}
