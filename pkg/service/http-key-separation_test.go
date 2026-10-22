package service

import (
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestHTTPSKeyReuseFailsRegardlessOfAuditFailurePolicy(t *testing.T) {
	for _, role := range []string{"SSH host", "audit signing", "audit recipient", "disabled audit recipient", "SFTP identity"} {
		for _, bestEffort := range []bool{false, true} {
			t.Run(role+map[bool]string{false: "/required", true: "/best effort"}[bestEffort], func(t *testing.T) {
				conf := httpListenerTestConfiguration(t)
				key, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).GenerateKey(nil)
				require.NoError(t, err)
				block, err := key.MarshalPemBlock()
				require.NoError(t, err)
				auditlog := &conf.Auditlogs[0]
				auditlog.Enabled = true
				if bestEffort {
					auditlog.FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
				}
				switch role {
				case "SSH host":
					paths, err := conf.Ssh.Keys.HostKeys.Render(noopContext{})
					require.NoError(t, err)
					require.NoError(t, crypto.WriteBootstrapFile(paths[0], pem.EncodeToMemory(block), false))
				case "audit signing":
					require.NoError(t, crypto.WriteBootstrapFile(auditlog.IdentityFile, pem.EncodeToMemory(block), false))
				case "audit recipient", "disabled audit recipient":
					if role == "disabled audit recipient" {
						auditlog.Enabled = false
					}
					auditlog.EncryptionPublicKey = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key.PublicKey().ToSsh()))))
				case "SFTP identity":
					// Use a copied file at an unrelated path: path checks alone cannot detect key reuse.
					path := filepath.Join(t.TempDir(), "sftp-key")
					require.NoError(t, crypto.WriteBootstrapFile(path, pem.EncodeToMemory(block), false))
					sftp := &configuration.AuditlogTargetSftp{}
					require.NoError(t, sftp.SetDefaults())
					sftp.Address = "127.0.0.1:1"
					sftp.User = template.MustNewString("archive")
					sftp.Directory = "/archive"
					sftp.AcceptAllHostKeys = true
					sftp.IdentityFiles = []string{path}
					auditlog.Targets = configuration.AuditlogTargets{{Name: "archive", V: sftp}}
				}
				httpListenerTestCertificate(t, &conf, key.ToSdk())
				_, err = (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
				require.ErrorContains(t, err, "HTTPS/ACME key must be distinct")
			})
		}
	}
}
