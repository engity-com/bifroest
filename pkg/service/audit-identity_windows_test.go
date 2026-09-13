//go:build windows

package service

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestValidateRuntimePathsRejectsWindowsSftpIdentityInsideSessionStorage(t *testing.T) {
	root := t.TempDir()
	storage := filepath.Join(root, "sessions")
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name:         "security",
			Enabled:      true,
			IdentityFile: filepath.Join(root, "identity"),
			Journal:      configuration.AuditlogJournal{Directory: filepath.Join(root, "journal")},
			Targets: configuration.AuditlogTargets{{
				Name: "archive",
				V: &configuration.AuditlogTargetSftp{
					IdentityFiles: []string{filepath.Join(storage, "archive-key")},
				},
			}},
		}},
		Session: configuration.Session{V: &configuration.SessionFs{Storage: storage}},
	}

	require.ErrorContains(t, validateRuntimePaths(&conf), "SFTP target \"archive\" identity file [0]")
}
