//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeJournalLocksCanonicalDirectory(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	require.NoError(t, os.MkdirAll(conf.Directory, journalDirectoryMode))
	alias := filepath.Join(filepath.Dir(conf.Directory), "journal-alias")
	require.NoError(t, os.Symlink(conf.Directory, alias))

	first, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	aliasConf := conf
	aliasConf.Directory = alias
	second, err := NewRecorder(&aliasConf, identity)
	require.Nil(t, second)
	require.ErrorContains(t, err, "already locked")
	require.NoError(t, first.Close())
}

func TestNativeJournalUsesRestrictiveModes(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Close())

	rootInfo, err := os.Stat(conf.Directory)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(journalDirectoryMode), rootInfo.Mode().Perm())
	producerInfo, err := os.Stat(filepath.Join(conf.Directory, identity.ProducerId().String()))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(journalDirectoryMode), producerInfo.Mode().Perm())
	activeInfo, err := os.Stat(journalTestActivePath(conf, identity))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(journalFileMode), activeInfo.Mode().Perm())
}
