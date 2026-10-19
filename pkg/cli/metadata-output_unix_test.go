//go:build unix

package cli

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	clibase "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func TestMetadataFileOutputDoesNotReadUnrelatedRepositories(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_METADATA_STDOUT") != "" {
		app := NewApplication[clibase.NoOptions](nil, "", nil).MustCreate()
		defer app.Close()
		ctx := clibase.ContextWithStdio(t.Context(), nil, os.Stdout, os.Stderr)
		require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}},
			"flow", "ls", "--format=json", "--configuration="+os.Getenv("BIFROEST_TEST_METADATA_CONFIG")))
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory read permissions")
	}
	root := t.TempDir()
	var directories []string
	for _, name := range []string{"sessions", "journal", "recordings"} {
		path := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(path, 0300))
		directories = append(directories, path)
		t.Cleanup(func() { require.NoError(t, os.Chmod(path, 0700)) })
		_, err := os.ReadDir(path)
		require.ErrorIs(t, err, fs.ErrPermission)
	}
	identity := filepath.Join(root, "identity")
	require.NoError(t, os.WriteFile(identity, []byte("metadata commands do not read this key"), 0600))
	raw, err := yaml.Marshal(map[string]any{
		"session": map[string]string{"type": "fs", "storage": directories[0]},
		"auditlog": []map[string]any{{
			"name": "default", "enabled": true, "identityFile": identity, "directory": directories[1],
			"recording": map[string]any{"enabled": true, "directory": directories[2]},
		}},
		"flows": []map[string]any{{
			"name": "local", "authorization": map[string]string{"type": "none"}, "environment": map[string]string{"type": "dummy"},
		}},
	})
	require.NoError(t, err)
	config := filepath.Join(root, "configuration.yaml")
	require.NoError(t, os.WriteFile(config, raw, 0600))
	output, err := os.Create(filepath.Join(root, "flows.json"))
	require.NoError(t, err)
	defer output.Close()
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMetadataFileOutputDoesNotReadUnrelatedRepositories$")
	command.Env = append(os.Environ(), "BIFROEST_TEST_METADATA_STDOUT=1", "BIFROEST_TEST_METADATA_CONFIG="+config)
	command.Stdout = output
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	require.NoError(t, command.Run(), diagnostics.String())
	content, err := os.ReadFile(output.Name())
	require.NoError(t, err)
	require.Contains(t, string(content), `"name":"local"`, "inherited stdout must be identified by its handle, not its /dev/stdout name")
}
