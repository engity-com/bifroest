package uuidpath

import (
	"github.com/engity-com/bifroest/pkg/uuidtext"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestUUIDStorageAliasesNeverChooseOrModifyAnAmbiguousIdentity(t *testing.T) {
	id, err := uuidtext.Parse("34e34ab8-7457-4d88-a5e4-c57791775c3a")
	require.NoError(t, err)
	for _, suffix := range []string{"", ".bcast", ".tmp"} {
		root := t.TempDir()
		current := filepath.Join(root, uuidtext.Format(id)+suffix)
		legacy := filepath.Join(root, uuidtext.Classic(id)+suffix)
		path, err := Resolve(root, id, suffix)
		require.NoError(t, err)
		require.Equal(t, current, path)
		require.NoError(t, os.WriteFile(legacy, []byte("legacy-original"), 0600))
		path, err = Resolve(root, id, suffix)
		require.NoError(t, err)
		require.Equal(t, legacy, path)
		require.NoError(t, CheckAliases(t.Context(), root, suffix))
		require.NoError(t, os.WriteFile(current, []byte("conflicting-original"), 0600))
		_, err = Resolve(root, id, suffix)
		require.ErrorContains(t, err, "ambiguous")
		require.ErrorContains(t, CheckAliases(t.Context(), root, suffix), "ambiguous")
		data, err := os.ReadFile(legacy)
		require.NoError(t, err)
		require.Equal(t, "legacy-original", string(data))
		data, err = os.ReadFile(current)
		require.NoError(t, err)
		require.Equal(t, "conflicting-original", string(data))
	}
}

func TestUUIDStorageNamesRejectPathEscapesBeforeInspectingAliases(t *testing.T) {
	id, err := uuidtext.Parse("34e34ab8-7457-4d88-a5e4-c57791775c3a")
	require.NoError(t, err)
	parent := t.TempDir()
	root := filepath.Join(parent, "storage")
	require.NoError(t, os.Mkdir(root, 0700))
	outside := filepath.Join(parent, "outside")
	require.NoError(t, os.WriteFile(outside, []byte("outside sentinel"), 0600))
	for _, suffix := range []string{"/../../outside", `\..\..\outside`, "/child", `\child`, ":stream", "\x00", ".", " "} {
		t.Run(suffix, func(t *testing.T) {
			path, exists, err := ResolveExisting(root, id, suffix)
			require.ErrorContains(t, err, "single local file component")
			require.Empty(t, path)
			require.False(t, exists)
			contents, err := os.ReadFile(outside)
			require.NoError(t, err)
			require.Equal(t, "outside sentinel", string(contents))
			entries, err := os.ReadDir(root)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}
