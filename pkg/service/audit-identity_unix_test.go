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
