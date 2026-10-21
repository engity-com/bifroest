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

func TestKeyExportCaUsesFlowConfigurationBeforeServiceStart(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "client-key")
	authorityFile := filepath.Join(directory, "ca")
	configurationFile := writeKeyExportCaTestConfiguration(t, directory, identityFile, authorityFile, true)

	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromFile(configurationFile))
	opts := exportOpts{Opts: configuration.Opts{Configuration: &conf}, Flow: "entry", Output: "-"}
	var stdout bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &stdout, nil)
	require.NoError(t, handleExport(ctx, opts))

	privateRaw, err := goos.ReadFile(authorityFile)
	require.NoError(t, err)
	private, err := ssh.ParsePrivateKey(privateRaw)
	require.NoError(t, err)
	public, comment, options, rest, err := ssh.ParseAuthorizedKey(stdout.Bytes())
	require.NoError(t, err)
	require.Empty(t, comment)
	require.Empty(t, options)
	require.Empty(t, bytes.TrimSpace(rest))
	require.Equal(t, private.PublicKey().Marshal(), public.Marshal())
	require.NoFileExists(t, authorityFile+".pub")
	require.NoFileExists(t, identityFile)
}

func TestKeyExportCaFileIsNoClobberUnlessForced(t *testing.T) {
	directory := t.TempDir()
	authorityFile := filepath.Join(directory, "ca")
	configurationFile := writeKeyExportCaTestConfiguration(t, directory, filepath.Join(directory, "client-key"), authorityFile, true)
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromFile(configurationFile))
	output := filepath.Join(directory, "ca.pub")
	opts := exportOpts{Opts: configuration.Opts{Configuration: &conf}, Flow: "entry", Output: output}

	require.NoError(t, handleExport(t.Context(), opts))
	require.Error(t, handleExport(t.Context(), opts))
	opts.Force = true
	require.NoError(t, handleExport(t.Context(), opts))
}

func TestKeyExportCaDoesNotReplacePrivateKeyWithForce(t *testing.T) {
	directory := t.TempDir()
	authorityFile := filepath.Join(directory, "ca")
	configurationFile := writeKeyExportCaTestConfiguration(t, directory, filepath.Join(directory, "client-key"), authorityFile, true)
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromFile(configurationFile))

	err := handleExport(t.Context(), exportOpts{Opts: configuration.Opts{Configuration: &conf}, Flow: "entry", Output: authorityFile, Force: true})
	require.ErrorContains(t, err, "must not replace private key")
	privateRaw, readErr := goos.ReadFile(authorityFile)
	require.NoError(t, readErr)
	_, parseErr := ssh.ParsePrivateKey(privateRaw)
	require.NoError(t, parseErr)
}

func TestKeyExportCaRejectsUnknownOrInapplicableFlow(t *testing.T) {
	directory := t.TempDir()
	configurationFile := writeKeyExportCaTestConfiguration(t, directory, filepath.Join(directory, "client-key"), filepath.Join(directory, "ca"), false)
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromFile(configurationFile))

	for _, flow := range []configuration.FlowName{"missing", "entry"} {
		err := handleExport(t.Context(), exportOpts{Opts: configuration.Opts{Configuration: &conf}, Flow: flow, Output: "-"})
		require.Error(t, err)
	}
}

func writeKeyExportCaTestConfiguration(t *testing.T, directory, identityFile, authorityFile string, certificate bool) string {
	t.Helper()
	certificateYaml := ""
	if certificate {
		certificateYaml = fmt.Sprintf("      certificate:\n        identityFile: %s\n        authorityIdentityFile: %s\n", identityFile, authorityFile)
	}
	raw := fmt.Sprintf(`flows:
  - name: entry
    authorization:
      type: simple
    environment:
      type: ssh
      address: target.example.org
      user: alice
      acceptAllHostKeys: true
%s`, certificateYaml)
	path := filepath.Join(directory, "configuration.yaml")
	require.NoError(t, goos.WriteFile(path, []byte(raw), 0600))
	return path
}
