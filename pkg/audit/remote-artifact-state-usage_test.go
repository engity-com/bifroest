package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoteArtifactReceiptStateUsageRetainsFreshCanonicalStatsAndBoundedLookup(t *testing.T) {
	names := []string{remoteArtifactReceiptFileName, remoteArtifactReceiptRetentionFileName, remoteArtifactReceiptCompletedFileName, remoteArtifactReceiptRetentionTempName, remoteArtifactReceiptTempFileName, remoteArtifactLifecycleFileName, remoteArtifactLifecycleTempName, remoteArtifactReceiptRetentionTempName + remoteArtifactReceiptCleanupSuffix, remoteArtifactReceiptTempFileName + remoteArtifactReceiptCleanupSuffix, remoteArtifactLifecycleTempName + remoteArtifactReceiptCleanupSuffix}
	for _, extra := range []int{0, 1, 32} {
		t.Run(fmt.Sprintf("extra=%d", extra), func(t *testing.T) {
			root := t.TempDir()
			for index := range extra {
				require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("unrelated-%d", index)), []byte("not receipt state"), 0600))
			}
			var expected int64
			for index, name := range names {
				data := bytes.Repeat([]byte("x"), index+1)
				require.NoError(t, os.WriteFile(filepath.Join(root, name), data, 0600))
				expected += int64(len(data))
				actual, err := remoteArtifactReceiptStateUsage(root)
				require.NoError(t, err)
				require.Equal(t, expected, actual)
			}
			require.NoError(t, os.WriteFile(filepath.Join(root, names[0]), []byte("fresh size"), 0600))
			actual, err := remoteArtifactReceiptStateUsage(root)
			require.NoError(t, err)
			require.Equal(t, expected-1+int64(len("fresh size")), actual)
			require.NoError(t, os.Remove(filepath.Join(root, names[0])))
			require.NoError(t, os.Mkdir(filepath.Join(root, names[0]), 0700))
			_, err = remoteArtifactReceiptStateUsage(root)
			require.ErrorContains(t, err, "invalid size", "enumeration must not bypass the fresh regular-file check")
		})
	}
}

func TestRemoteArtifactReceiptStateUsagePreservesNativeCaseAliasesAndMissingDirectories(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, strings.ToUpper(remoteArtifactReceiptFileName)), []byte("receipt bytes"), 0600))
	var expected int64
	info, err := os.Lstat(filepath.Join(root, remoteArtifactReceiptFileName))
	if os.IsNotExist(err) {
		expected = 0
	} else {
		require.NoError(t, err)
		expected = info.Size()
	}
	actual, err := remoteArtifactReceiptStateUsage(root)
	require.NoError(t, err)
	require.Equal(t, expected, actual, "case-sensitive hosts must not count unknown files; case-insensitive hosts must not miss canonical state")
	actual, err = remoteArtifactReceiptStateUsage(filepath.Join(root, "missing"))
	require.NoError(t, err)
	require.Zero(t, actual)
}

func TestRemoteArtifactReceiptStateNamesRetainAmbiguousNativeLookups(t *testing.T) {
	names := []string{remoteArtifactReceiptFileName, remoteArtifactReceiptTempFileName, remoteArtifactLifecycleFileName}
	root := t.TempDir()
	selected, err := remoteArtifactReceiptStateNames(root, names)
	require.NoError(t, err)
	require.Contains(t, selected, remoteArtifactReceiptTempFileName, "always probe the canonical 8.3 path independently")
	// A filesystem may fold this spelling differently from Unicode EqualFold.
	// Unknown directory names must preserve every original canonical lookup.
	require.NoError(t, os.WriteFile(filepath.Join(root, "receıpt.json"), []byte("untrusted alias spelling"), 0600))
	selected, err = remoteArtifactReceiptStateNames(root, names)
	require.NoError(t, err)
	require.Equal(t, names, selected)
}
