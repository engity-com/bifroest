package common

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestOutputAliasCheckFindsProtectedFilesAcrossDirectoryBatches(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "protected")
	require.NoError(t, os.Mkdir(protected, 0700))
	for index := range 1025 {
		require.NoError(t, os.WriteFile(filepath.Join(protected, fmt.Sprintf("%04d", index)), []byte("evidence"), 0600))
	}
	alias := filepath.Join(root, "output")
	if err := os.Link(filepath.Join(protected, "1024"), alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	info, err := os.Stat(alias)
	require.NoError(t, err)
	require.ErrorContains(t, EnsureFileDoesNotAliasDirectoryFile(t.Context(), alias, info, protected, "evidence"), "must not replace")
	safe := filepath.Join(root, "safe-output")
	require.NoError(t, os.WriteFile(safe, nil, 0600))
	info, err = os.Stat(safe)
	require.NoError(t, err)
	require.NoError(t, EnsureFileDoesNotAliasDirectoryFile(t.Context(), safe, info, protected, "evidence"))
}

func TestOutputSafetyChecksRespectCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, EnsureStandardOutputSafe(ctx, io.Discard, "", nil, nil), context.Canceled)
	require.ErrorIs(t, EnsureFileDoesNotAliasDirectoryFile(ctx, "unused", nil, "unused", "evidence"), context.Canceled)
}

func TestSingleLinkOutputDoesNotReadUnrelatedProtectedDirectory(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "sessions")
	require.NoError(t, os.Mkdir(protected, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(protected, "state"), []byte("keep"), 0600))
	output, err := os.Create(filepath.Join(root, "safe-output"))
	require.NoError(t, err)
	defer output.Close()
	info, err := output.Stat()
	require.NoError(t, err)
	location, err := inspectOutputLocation(t.Context(), output, info)
	require.NoError(t, err)
	if location == nil || !location.mount.matches(protected) {
		t.Skip("the platform cannot prove the output's single-link location and mount")
	}
	denyOutputDirectoryListing(t, protected)
	conf := &configuration.Configuration{Session: configuration.Session{V: &configuration.SessionFs{Storage: protected}}}
	require.NoError(t, EnsureStandardOutputSafe(t.Context(), output, "", conf, nil))
	_, err = output.WriteString("safe metadata output\n")
	require.NoError(t, err)
}

func TestOutputLocationProtectsDirectoryAliases(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "protected")
	require.NoError(t, os.Mkdir(protected, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	path := filepath.Join(protected, "state")
	require.NoError(t, os.WriteFile(path, []byte("keep"), 0600))
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	defer output.Close()
	conf := &configuration.Configuration{Session: configuration.Session{V: &configuration.SessionFs{Storage: alias}}}
	require.ErrorContains(t, EnsureStandardOutputSafe(t.Context(), output, "", conf, nil), "must not replace")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "keep", string(content))
}

func TestMultiplyLinkedOutputRetainsInventoryCheck(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "sessions")
	require.NoError(t, os.Mkdir(protected, 0700))
	path := filepath.Join(root, "output")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	if err := os.Link(path, path+"-alias"); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	defer output.Close()
	info, err := output.Stat()
	require.NoError(t, err)
	location, err := inspectOutputLocation(t.Context(), output, info)
	require.NoError(t, err)
	require.Nil(t, location, "multiple links cannot be excluded by one path")
	conf := &configuration.Configuration{Session: configuration.Session{V: &configuration.SessionFs{Storage: protected}}}
	require.NoError(t, EnsureStandardOutputSafe(t.Context(), output, "", conf, nil), "safe hard-linked outputs remain supported")
	if err := os.Link(path, filepath.Join(protected, "state")); err != nil {
		t.Fatal(err)
	}
	require.ErrorContains(t, EnsureStandardOutputSafe(t.Context(), output, "", conf, nil), "must not replace")
}

func TestOutputLocationRequiresInventoryForSubtreeMounts(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "protected")
	require.NoError(t, os.Mkdir(protected, 0700))
	require.False(t, hasMountBelow(protected, []string{protected, protected + "-sibling"}))
	require.True(t, hasMountBelow(protected, []string{filepath.Join(protected, "mounted-subtree")}))
	require.True(t, hasMountBelow(filepath.Join(root, "missing"), nil), "an unresolved directory cannot establish mount isolation")
}
