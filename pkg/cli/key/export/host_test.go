package export

import (
	"bytes"
	"fmt"
	goos "os"
	"path/filepath"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestKeyExportHostCreatesExplicitKeyAndUsesNoClobber(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "identity")

	hostKeyFile := filepath.Join(directory, "host-key")
	opts := hostOpts{IdentityFile: identityFile, Address: "host.example", Output: hostKeyFile}
	require.NoError(t, executeHostForTest(t, opts, &bytes.Buffer{}))
	require.FileExists(t, identityFile)
	require.Error(t, executeHostForTest(t, opts, &bytes.Buffer{}))
}

func TestKeyExportHostDoesNotReplacePrivateKeyWithForce(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "identity")
	opts := hostOpts{IdentityFile: identityFile, Address: "host.example", Output: identityFile, Force: true}

	err := executeHostForTest(t, opts, &bytes.Buffer{})
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
	opts := hostOpts{EmptyStrOpts: configuration.EmptyStrOpts{Configuration: configurationFile}, Address: "host.example", Output: "-"}
	require.NoError(t, executeHostForTest(t, opts, &stdout))
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

	opts.Output = first
	opts.Force = true
	require.ErrorContains(t, executeHostForTest(t, opts, &bytes.Buffer{}), "must not replace private key")
}

func TestKeyExportHostRejectsConfigurationWithIdentityFile(t *testing.T) {
	err := executeHostForTest(t, hostOpts{
		EmptyStrOpts: configuration.EmptyStrOpts{Configuration: "configuration.yaml"},
		IdentityFile: "identity",
		Address:      "host.example",
		Output:       "-",
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

	err := executeHostForTest(t, hostOpts{
		EmptyStrOpts: configuration.EmptyStrOpts{Configuration: configurationFile},
		Address:      "host.example",
		Output:       identityFile,
		Force:        true,
	}, &bytes.Buffer{})
	require.ErrorContains(t, err, "must not replace private key")
	privateRaw, readErr := goos.ReadFile(identityFile)
	require.NoError(t, readErr)
	_, parseErr := ssh.ParsePrivateKey(privateRaw)
	require.NoError(t, parseErr)
}

func executeHostForTest(t *testing.T, options hostOpts, output *bytes.Buffer) error {
	t.Helper()
	ctx := cli.ContextWithStdio(t.Context(), nil, output, nil)
	return handleHost(ctx, options)
}
