package management

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
)

func TestManagementOutputDoesNotReplaceSSHInputs(t *testing.T) {
	for _, input := range []string{"identity", "known-hosts"} {
		for _, alias := range []bool{false, true} {
			name := "direct"
			if alias {
				name = "hardlink"
			}
			t.Run(input+"/"+name, func(t *testing.T) {
				target, done := managementClientTestServer(t, transport.WireCommand, func(channel ssh.Channel, _ []string) error {
					encoded, err := transport.EncodeWireResult([]model.FlowSummary{{Name: "main", Auditlog: "default"}})
					if err != nil {
						return err
					}
					if _, err := channel.Write(encoded); err != nil {
						return err
					}
					_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return err
				})
				conf, err := resolve(target)
				require.NoError(t, err)
				protected := conf.identities[0]
				if input == "known-hosts" {
					protected = conf.knownHosts[0]
				}
				before, err := os.ReadFile(protected)
				require.NoError(t, err)
				destination := protected
				if alias {
					destination = filepath.Join(t.TempDir(), "output-alias")
					if err := os.Link(protected, destination); err != nil {
						t.Skipf("hard links unavailable: %v", err)
					}
				}
				output, err := os.OpenFile(destination, os.O_WRONLY|os.O_APPEND, 0)
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				require.ErrorContains(t, target.EnsureOutputSafe(ctx, destination, io.Discard), "must not replace")
				err = target.Run(cli.ContextWithStdio(ctx, nil, output, nil), "flow", "ls", "--format=json")
				require.NoError(t, output.Close())
				after, readErr := os.ReadFile(protected)
				require.NoError(t, readErr)
				require.True(t, bytes.Equal(before, after), "management output modified an SSH input file")
				require.ErrorContains(t, err, "must not replace")
				var control bytes.Buffer
				require.NoError(t, target.Run(cli.ContextWithStdio(ctx, nil, &control, nil), "flow", "ls", "--format=json"))
				require.Contains(t, control.String(), "main")
				require.NoError(t, <-done)
			})
		}
	}
}

func TestManagementOutputProtectsPrimarySSHConfigurationAliases(t *testing.T) {
	root := t.TempDir()
	userConfig := filepath.Join(root, "user-config")
	systemConfig := filepath.Join(root, "system-config")
	selectedConfig := filepath.Join(root, "selected-config")
	contents := []byte("# preserve SSH configuration\n")
	for _, path := range []string{userConfig, systemConfig, selectedConfig} {
		require.NoError(t, os.WriteFile(path, contents, 0600))
	}
	for source, files := range map[string][]string{
		"default":  {userConfig, systemConfig},
		"selected": {selectedConfig},
	} {
		t.Run(source, func(t *testing.T) {
			conf := settings{configurationFiles: files}
			for _, path := range files {
				for _, alias := range []string{"direct", "symlink", "hardlink"} {
					t.Run(filepath.Base(path)+"/"+alias, func(t *testing.T) {
						destination := path
						if alias != "direct" {
							destination = filepath.Join(t.TempDir(), "output-alias")
							link := os.Link
							if alias == "symlink" {
								link = os.Symlink
							}
							if err := link(path, destination); err != nil {
								t.Skipf("%s unavailable: %v", alias, err)
							}
						}
						require.ErrorContains(t, ensureSSHInputOutputSafe(t.Context(), conf, destination, nil), "must not replace SSH client configuration")
						output, err := os.OpenFile(destination, os.O_WRONLY|os.O_APPEND, 0)
						require.NoError(t, err)
						err = ensureSSHInputOutputSafe(t.Context(), conf, "-", output)
						require.NoError(t, output.Close())
						require.ErrorContains(t, err, "must not replace SSH client configuration")
						after, err := os.ReadFile(path)
						require.NoError(t, err)
						require.Equal(t, contents, after)
					})
				}
			}
			// Only the primary sources selected for this invocation are protected.
			unused := []string{selectedConfig}
			if source == "selected" {
				unused = []string{userConfig, systemConfig}
			}
			for _, path := range unused {
				require.NoError(t, ensureSSHInputOutputSafe(t.Context(), conf, path, nil))
			}
			require.NoError(t, ensureSSHInputOutputSafe(t.Context(), conf, filepath.Join(root, "export.json"), nil))
			require.NoError(t, ensureSSHInputOutputSafe(t.Context(), conf, "-", &bytes.Buffer{}))
		})
	}
}

func TestManagementOutputDoesNotCreatePrimarySSHConfigurations(t *testing.T) {
	for _, path := range []string{
		filepath.Join(t.TempDir(), ".ssh", "config"),
		filepath.Join(t.TempDir(), "etc", "ssh", "ssh_config"),
	} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			conf := settings{configurationFiles: []string{path}}
			require.ErrorContains(t, ensureSSHInputOutputSafe(t.Context(), conf, path, nil), "must not replace SSH client configuration")
			require.NoFileExists(t, path)
			require.NoDirExists(t, filepath.Dir(path))
		})
	}
}
