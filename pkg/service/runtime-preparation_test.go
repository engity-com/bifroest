package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestRuntimePreparationRejectsMissingBootstrapWithoutChangingAcceptedState(t *testing.T) {
	for _, kind := range []string{"password", "subject", "authority"} {
		t.Run(kind, func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			conf := svc.generation.snapshot.Configuration()
			before, err := svc.runtime.persistence.repository.RuntimeState(t.Context())
			require.NoError(t, err)
			root := t.TempDir()
			missing := filepath.Join(root, "missing")
			if kind == "password" {
				passwordType := crypto.PasswordTypePlain
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries = configuration.AuthorizationSimpleEntries{{
					Name: "alice", PasswordFile: crypto.PasswordFile(missing), CreatePasswordFileIfAbsentOfType: &passwordType,
				}}
			} else {
				ssh := &configuration.EnvironmentSsh{}
				require.NoError(t, ssh.SetDefaults())
				ssh.Address, ssh.User = template.MustNewString("target.example.org:22"), template.MustNewString("alice")
				ssh.AcceptAllHostKeys = true
				ssh.Certificate = &configuration.EnvironmentSshCertificate{}
				require.NoError(t, ssh.Certificate.SetDefaults())
				subject, authority := missing, filepath.Join(root, "authority")
				if kind == "authority" {
					subject, authority = filepath.Join(root, "subject"), missing
					_, err := crypto.EnsureKeyFile(subject, &crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}, nil)
					require.NoError(t, err)
				}
				ssh.Certificate.IdentityFile, ssh.Certificate.AuthorityIdentityFile = template.MustNewString(subject), template.MustNewString(authority)
				conf.Flows[0].Environment.V = ssh
			}
			candidate, err := svc.prepareGeneration(t.Context(), conf)
			require.ErrorIs(t, err, common.ErrProviderBootstrapDisabled)
			require.Nil(t, candidate)
			require.NoFileExists(t, missing)
			require.Same(t, svc.generation, svc.runtime.current)
			after, err := svc.runtime.persistence.repository.RuntimeState(t.Context())
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.True(t, runtimeAdmissionTestPassword(t, svc, "correct").IsAuthorized())
			svc.resources.keysMutex.Lock()
			require.Empty(t, svc.resources.sshKeys)
			svc.resources.keysMutex.Unlock()
		})
	}
}

func TestRuntimePreparationDiscardPreservesProvisionedFilesAndCurrentAccess(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "discard", true: "later-provider-failure"}[fail], func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			conf := svc.generation.snapshot.Configuration()
			root := t.TempDir()
			passwordPath := filepath.Join(root, "password")
			require.NoError(t, os.WriteFile(passwordPath, []byte("plain:new-password"), 0600))
			passwordType := crypto.PasswordTypePlain
			conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries = configuration.AuthorizationSimpleEntries{{
				Name: "alice", PasswordFile: crypto.PasswordFile(passwordPath), CreatePasswordFileIfAbsentOfType: &passwordType,
			}}
			ssh := &configuration.EnvironmentSsh{}
			require.NoError(t, ssh.SetDefaults())
			ssh.Address, ssh.User = template.MustNewString("target.example.org:22"), template.MustNewString("alice")
			ssh.AcceptAllHostKeys = !fail
			if fail {
				ssh.KnownHostsFile = crypto.KnownHostsFile(filepath.Join(root, "missing-known-hosts"))
			}
			ssh.Certificate = &configuration.EnvironmentSshCertificate{}
			require.NoError(t, ssh.Certificate.SetDefaults())
			subject, authority := filepath.Join(root, "subject"), filepath.Join(root, "authority")
			ssh.Certificate.IdentityFile, ssh.Certificate.AuthorityIdentityFile = template.MustNewString(subject), template.MustNewString(authority)
			conf.Flows[0].Environment.V = ssh
			before := make(map[string][]byte)
			for _, path := range []string{subject, authority} {
				_, err := crypto.EnsureKeyFile(path, &crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}, nil)
				require.NoError(t, err)
				before[path], err = os.ReadFile(path)
				require.NoError(t, err)
			}
			before[passwordPath] = []byte("plain:new-password")
			candidate, err := svc.prepareGeneration(t.Context(), conf)
			if fail {
				require.Error(t, err)
				require.Nil(t, candidate)
			} else {
				require.NoError(t, err)
				require.NoError(t, candidate.Close())
			}
			for path, raw := range before {
				after, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, raw, after, "discard never deletes or rewrites provisioned files")
			}
			require.Same(t, svc.generation, svc.runtime.current)
			require.True(t, runtimeAdmissionTestPassword(t, svc, "correct").IsAuthorized())
		})
	}
}
