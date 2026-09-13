//go:build unix

package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestLocalJournalLocksCanonicalDirectory(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	require.NoError(t, os.MkdirAll(conf.Journal.Directory, journalDirectoryMode))
	alias := filepath.Join(filepath.Dir(conf.Journal.Directory), "journal-alias")
	require.NoError(t, os.Symlink(conf.Journal.Directory, alias))

	first, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	aliasConf := conf
	aliasConf.Journal.Directory = alias
	second, err := NewRecorder(&aliasConf, identity)
	require.Nil(t, second)
	require.ErrorContains(t, err, "already locked")
	require.NoError(t, first.Close())
}

func TestLocalJournalUsesRestrictiveModes(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Close())

	rootInfo, err := os.Stat(conf.Journal.Directory)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(journalDirectoryMode), rootInfo.Mode().Perm())
	producerInfo, err := os.Stat(filepath.Join(conf.Journal.Directory, identity.ProducerId().String()))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(journalDirectoryMode), producerInfo.Mode().Perm())
	activeInfo, err := os.Stat(journalTestActivePath(conf, identity))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(journalFileMode), activeInfo.Mode().Perm())
}

func TestLocalJournalRejectsInsecureExistingModes(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Close())

	activePath := journalTestActivePath(conf, identity)
	require.NoError(t, os.Chmod(activePath, 0660))
	failed, err := NewRecorder(&conf, identity)
	require.Nil(t, failed)
	require.ErrorContains(t, err, "insecure permissions")
	require.True(t, berrors.Config.IsErr(err))
	require.NoError(t, os.Chmod(activePath, journalFileMode))

	require.NoError(t, os.Chmod(conf.Journal.Directory, 0750))
	failed, err = NewRecorder(&conf, identity)
	require.Nil(t, failed)
	require.ErrorContains(t, err, "insecure permissions")
	require.NoError(t, os.Chmod(conf.Journal.Directory, journalDirectoryMode))
}

func TestLocalJournalRejectsSymlinkedLockFile(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	require.NoError(t, os.MkdirAll(conf.Journal.Directory, journalDirectoryMode))
	target := filepath.Join(filepath.Dir(conf.Journal.Directory), "outside-lock")
	require.NoError(t, os.WriteFile(target, nil, journalFileMode))
	require.NoError(t, os.Symlink(target, filepath.Join(conf.Journal.Directory, journalLockFileName)))

	failed, err := NewRecorder(&conf, identity)

	require.Nil(t, failed)
	require.ErrorContains(t, err, "is not a regular file")
}

func TestLocalJournalRecoversInterruptedHardLinkPublication(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.before-publish-crash"}))
	sealed := appendSealAndCrashCloseJournalTestRecorder(t, recorder)

	activePath := journalTestActivePath(conf, identity)
	require.NoError(t, os.Chmod(activePath, 0400))
	targetPath := filepath.Join(producerJournalTestDirectory(conf, identity), sealedJournalFileName(sealed.sequence, sealed.segmentHash))
	require.NoError(t, os.Link(activePath, targetPath))

	recovered, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	activeInfo, err := os.Stat(activePath)
	require.NoError(t, err)
	targetInfo, err := os.Stat(targetPath)
	require.NoError(t, err)
	require.False(t, os.SameFile(activeInfo, targetInfo))
	require.Equal(t, os.FileMode(0400), targetInfo.Mode().Perm())
	require.Equal(t, uint64(2), recovered.(*localJournalRecorder).state.sequence)
	require.Len(t, readJournalTestRecords(t, conf, identity), 1)
	require.NoError(t, recovered.Close())
}
