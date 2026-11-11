package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestEnsureSharedIdentityDoesNotRegenerateForAnotherRepository(t *testing.T) {
	for _, kind := range []string{"journal", "journal workspace", "recording", "disabled recording"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			first := auditIdentityTestConfiguration(root)
			second := first
			second.Name = "other"
			second.Directory = filepath.Join(root, "other-journal")
			second.Recording.Directory = filepath.Join(root, "other-recordings")
			second.Recording.Enabled = kind == "recording"
			path := second.Directory
			switch kind {
			case "journal workspace":
				path = filepath.Join(second.Directory, journalWorkDirectoryName)
			case "recording", "disabled recording":
				path = second.Recording.Directory
			}
			require.NoError(t, os.MkdirAll(path, 0700))
			marker := filepath.Join(path, "existing-state")
			require.NoError(t, os.WriteFile(marker, []byte("original evidence"), 0600))
			identity, err := EnsureIdentityWithAuditlogs(&first, configuration.Auditlogs{first, second})
			require.Nil(t, identity)
			require.ErrorContains(t, err, "is missing while")
			require.NoFileExists(t, first.IdentityFile)
			original, err := os.ReadFile(marker)
			require.NoError(t, err)
			require.Equal(t, "original evidence", string(original))
		})
	}
}

func TestEnsureSharedIdentityRecognizesMissingKeyDirectoryAlias(t *testing.T) {
	root := t.TempDir()
	first := auditIdentityTestConfiguration(root)
	require.NoError(t, os.MkdirAll(filepath.Dir(first.IdentityFile), 0700))
	alias := filepath.Join(root, "key-directory-alias")
	if err := os.Symlink(filepath.Dir(first.IdentityFile), alias); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	second := first
	second.Name = "other"
	second.IdentityFile = filepath.Join(alias, filepath.Base(first.IdentityFile))
	second.Directory = filepath.Join(root, "other-journal")
	require.NoError(t, os.MkdirAll(second.Directory, 0700))
	marker := filepath.Join(second.Directory, "existing-state")
	require.NoError(t, os.WriteFile(marker, []byte("original evidence"), 0600))
	identity, err := EnsureIdentityWithAuditlogs(&first, configuration.Auditlogs{first, second})
	require.Nil(t, identity)
	require.ErrorContains(t, err, "is missing while")
	require.NoFileExists(t, first.IdentityFile)
	contents, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "original evidence", string(contents))
}
