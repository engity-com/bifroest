//go:build darwin

package user

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinChownHomeRejectsSymlinks(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("outside"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(home, "link")))
	repository := &DarwinRepository{}

	err := repository.chownDarwinHome(t.Context(), home, Id(os.Geteuid()), GroupId(os.Getegid()))
	require.ErrorContains(t, err, "symlink")
	contents, readErr := os.ReadFile(outside)
	require.NoError(t, readErr)
	require.Equal(t, []byte("outside"), contents)
}

func TestCopyDarwinSkeletonRejectsSymlinks(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(source, "link")))

	err := copyDarwinSkeleton(t.Context(), source, destination)
	require.ErrorContains(t, err, "unsupported skeleton entry")
	_, err = os.Stat(filepath.Join(destination, "link"))
	require.True(t, os.IsNotExist(err))
}

func TestStageDarwinHomeReplacementRestoresOriginalOnRollback(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	require.NoError(t, os.Mkdir(home, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "original"), []byte("original"), 0600))
	info, err := os.Lstat(home)
	require.NoError(t, err)
	transaction := &darwinMutation{}

	require.NoError(t, stageDarwinHomeReplacement(home, info, transaction))
	require.NoError(t, os.Mkdir(home, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "replacement"), []byte("replacement"), 0600))
	replacement, err := os.Lstat(home)
	require.NoError(t, err)
	transaction.onRollback(func(context.Context) error {
		return removeDarwinTreeIfSame(home, replacement)
	})
	require.NoError(t, transaction.rollback(context.Background()))

	contents, err := os.ReadFile(filepath.Join(home, "original"))
	require.NoError(t, err)
	require.Equal(t, []byte("original"), contents)
	_, err = os.Stat(filepath.Join(home, "replacement"))
	require.True(t, os.IsNotExist(err))
}

func TestStageDarwinHomeReplacementKeepsReplacementOnCommit(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	require.NoError(t, os.Mkdir(home, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "original"), []byte("original"), 0600))
	info, err := os.Lstat(home)
	require.NoError(t, err)
	transaction := &darwinMutation{}

	require.NoError(t, stageDarwinHomeReplacement(home, info, transaction))
	require.NoError(t, os.Mkdir(home, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "replacement"), []byte("replacement"), 0600))
	require.NoError(t, transaction.commit(context.Background()))

	contents, err := os.ReadFile(filepath.Join(home, "replacement"))
	require.NoError(t, err)
	require.Equal(t, []byte("replacement"), contents)
	entries, err := os.ReadDir(parent)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "home", entries[0].Name())
}

func TestStageDarwinHomeReplacementDoesNotDeleteUnknownOccupant(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	require.NoError(t, os.Mkdir(home, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "original"), []byte("original"), 0600))
	info, err := os.Lstat(home)
	require.NoError(t, err)
	transaction := &darwinMutation{}

	require.NoError(t, stageDarwinHomeReplacement(home, info, transaction))
	require.NoError(t, os.Mkdir(home, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "unknown"), []byte("unknown"), 0600))
	err = transaction.rollback(context.Background())
	require.ErrorContains(t, err, "occupied path")

	contents, err := os.ReadFile(filepath.Join(home, "unknown"))
	require.NoError(t, err)
	require.Equal(t, []byte("unknown"), contents)
}

func TestValidateDarwinHomePathRejectsTopLevelDirectory(t *testing.T) {
	_, err := validateDarwinHomePath("/Users")
	require.ErrorContains(t, err, "unsafe home")

	home, err := validateDarwinHomePath("/Users/alice")
	require.NoError(t, err)
	require.Equal(t, "/Users/alice", home)
}

func TestRejectDarwinHomeOverlapIncludesNestedHomes(t *testing.T) {
	users := []*darwinUserRecord{{name: "bob", homeDir: "/Users/bob"}}
	require.ErrorContains(t, rejectDarwinHomeOverlap("/Users", "alice", users), "shared home")
	require.ErrorContains(t, rejectDarwinHomeOverlap("/Users/bob/project", "alice", users), "shared home")
	require.NoError(t, rejectDarwinHomeOverlap("/Users/alice", "alice", users))
}

func TestRejectDarwinHomeOverlapResolvesFilesystemAliases(t *testing.T) {
	parent := t.TempDir()
	realParent := filepath.Join(parent, "real")
	require.NoError(t, os.Mkdir(realParent, 0700))
	home := filepath.Join(realParent, "alice")
	require.NoError(t, os.Mkdir(home, 0700))
	alias := filepath.Join(parent, "alias")
	require.NoError(t, os.Symlink(realParent, alias))

	err := rejectDarwinHomeOverlap(filepath.Join(alias, "alice"), "bob", []*darwinUserRecord{{name: "alice", homeDir: home}})
	require.ErrorContains(t, err, "shared home")
}

func TestSnapshotDarwinHomeOwnershipRejectsHardLinks(t *testing.T) {
	home := t.TempDir()
	original := filepath.Join(home, "original")
	require.NoError(t, os.WriteFile(original, []byte("contents"), 0600))
	require.NoError(t, os.Link(original, filepath.Join(home, "link")))

	_, err := snapshotDarwinHomeOwnership(home)
	require.ErrorContains(t, err, "multiply linked")
}
