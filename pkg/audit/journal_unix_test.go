//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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
