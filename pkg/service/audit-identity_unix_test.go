//go:build unix

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestValidateAuditlogRuntimePathsResolvesSymlinkedParents(t *testing.T) {
	directory := t.TempDir()
	realJournal := filepath.Join(directory, "journal")
	require.NoError(t, os.Mkdir(realJournal, 0700))
	journalAlias := filepath.Join(directory, "journal-alias")
	require.NoError(t, os.Symlink(realJournal, journalAlias))

	auditlogs := configuration.Auditlogs{
		{Name: "first", Enabled: true, IdentityFile: filepath.Join(directory, "first-key"), Journal: configuration.AuditlogJournal{Directory: realJournal}},
		{Name: "second", Enabled: true, IdentityFile: filepath.Join(directory, "second-key"), Journal: configuration.AuditlogJournal{Directory: filepath.Join(journalAlias, "second")}},
	}

	err := validateAuditlogRuntimePaths(auditlogs)
	require.ErrorContains(t, err, "journal overlaps")
	require.NoDirExists(t, filepath.Join(realJournal, "second"))
}

func TestValidateRuntimePathsResolvesSessionStorageSymlinkedParent(t *testing.T) {
	directory := t.TempDir()
	realRoot := filepath.Join(directory, "real")
	require.NoError(t, os.Mkdir(realRoot, 0700))
	aliasRoot := filepath.Join(directory, "alias")
	require.NoError(t, os.Symlink(realRoot, aliasRoot))
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(directory, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: realRoot},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: filepath.Join(aliasRoot, "sessions")}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "journal")
	require.NoDirExists(t, filepath.Join(realRoot, "sessions"))
}

func TestValidateRuntimePathsResolvesSymlinkedSftpIdentityParent(t *testing.T) {
	directory := t.TempDir()
	storage := filepath.Join(directory, "sessions")
	require.NoError(t, os.Mkdir(storage, 0700))
	alias := filepath.Join(directory, "session-alias")
	require.NoError(t, os.Symlink(storage, alias))
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(directory, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: filepath.Join(directory, "journal")},
			Targets: configuration.AuditlogTargets{{
				Name: "archive",
				V: &configuration.AuditlogTargetSftp{
					IdentityFiles: []string{filepath.Join(alias, "archive-key")},
				},
			}},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: storage}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "SFTP target \"archive\" identity file [0]")
}
