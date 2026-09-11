package main

import (
	"bytes"
	"fmt"
	goos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestKeyExportCaUsesFlowConfigurationBeforeServiceStart(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "client-key")
	authorityFile := filepath.Join(directory, "ca")
	configurationFile := writeKeyExportCaTestConfiguration(t, directory, identityFile, authorityFile, true)

	var ref configuration.Ref
	require.NoError(t, ref.Set(configurationFile))
	opts := keyExportCaOpts{configuration: ref, flow: "entry", output: "-"}
	var stdout bytes.Buffer
	require.NoError(t, doKeyExportCa(&opts, &stdout))

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
	var ref configuration.Ref
	require.NoError(t, ref.Set(configurationFile))
	output := filepath.Join(directory, "ca.pub")
	opts := keyExportCaOpts{configuration: ref, flow: "entry", output: output}

	require.NoError(t, doKeyExportCa(&opts, &bytes.Buffer{}))
	require.Error(t, doKeyExportCa(&opts, &bytes.Buffer{}))
	opts.force = true
	require.NoError(t, doKeyExportCa(&opts, &bytes.Buffer{}))
}

func TestKeyExportCaDoesNotReplacePrivateKeyWithForce(t *testing.T) {
	directory := t.TempDir()
	authorityFile := filepath.Join(directory, "ca")
	configurationFile := writeKeyExportCaTestConfiguration(t, directory, filepath.Join(directory, "client-key"), authorityFile, true)
	var ref configuration.Ref
	require.NoError(t, ref.Set(configurationFile))

	err := doKeyExportCa(&keyExportCaOpts{configuration: ref, flow: "entry", output: authorityFile, force: true}, &bytes.Buffer{})
	require.ErrorContains(t, err, "must not replace private key")
	privateRaw, readErr := goos.ReadFile(authorityFile)
	require.NoError(t, readErr)
	_, parseErr := ssh.ParsePrivateKey(privateRaw)
	require.NoError(t, parseErr)
}

func TestKeyExportCaRejectsUnknownOrInapplicableFlow(t *testing.T) {
	directory := t.TempDir()
	configurationFile := writeKeyExportCaTestConfiguration(t, directory, filepath.Join(directory, "client-key"), filepath.Join(directory, "ca"), false)
	var ref configuration.Ref
	require.NoError(t, ref.Set(configurationFile))

	for _, flow := range []configuration.FlowName{"missing", "entry"} {
		err := doKeyExportCa(&keyExportCaOpts{configuration: ref, flow: flow, output: "-"}, &bytes.Buffer{})
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
