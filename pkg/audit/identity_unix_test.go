//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureIdentityRejectsInsecureUnixKeyFiles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, string)
		error   string
	}{
		{"permissions", func(t *testing.T, path string) {
			_, err := auditIdentityKeyRequirement.CreateFile(nil, path)
			require.NoError(t, err)
			require.NoError(t, os.Chmod(path, 0640))
		}, "accessible by group or others"},
		{"hard link", func(t *testing.T, path string) {
			_, err := auditIdentityKeyRequirement.CreateFile(nil, path)
			require.NoError(t, err)
			require.NoError(t, os.Link(path, path+".link"))
		}, "hard links"},
		{"symbolic link", func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(path), "target")
			_, err := auditIdentityKeyRequirement.CreateFile(nil, target)
			require.NoError(t, err)
			require.NoError(t, os.Symlink(target, path))
		}, "not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := auditIdentityTestConfiguration(t.TempDir(), true)
			tc.prepare(t, conf.IdentityFile)

			identity, err := EnsureIdentity(&conf)

			require.Nil(t, identity)
			require.ErrorContains(t, err, tc.error)
		})
	}
}
