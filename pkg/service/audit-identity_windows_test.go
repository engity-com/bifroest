//go:build windows

package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
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

func TestValidateRuntimePathsRejectsWindowsHostKeyJunctionIntoJournal(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	journal := filepath.Join(real, "journal")
	require.NoError(t, os.MkdirAll(journal, 0700))
	alias := filepath.Join(root, "journal-alias")
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", alias, real).CombinedOutput(); err != nil {
		t.Skipf("cannot create Windows junction: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	keyPath := filepath.Join(alias, "journal", "host-key")
	storedPath := filepath.Join(journal, "host-key")
	require.NoError(t, os.WriteFile(storedPath, []byte("unchanged"), 0600))
	conf := configuration.Configuration{
		Auditlogs: configuration.Auditlogs{{
			Name: "security", Enabled: true, IdentityFile: filepath.Join(root, "audit-identity"),
			Journal: configuration.AuditlogJournal{Directory: journal},
		}},
	}
	conf.Ssh.Keys.HostKeys = template.MustNewStrings(keyPath)
	err := validateRuntimePaths(&conf)
	require.Error(t, err)
	if !strings.Contains(err.Error(), "overlaps auditlog \"security\" journal") {
		// Some WSL-mounted Windows filesystems cannot resolve this junction at all.
		require.ErrorContains(t, err, "cannot resolve SSH host key")
	}
	content, err := os.ReadFile(storedPath)
	require.NoError(t, err)
	require.Equal(t, "unchanged", string(content))
}
