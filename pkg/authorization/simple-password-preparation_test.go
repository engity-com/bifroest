package authorization

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestSimpleAuthorizerPreparesPasswordFilesAtRuntimeNotDuringValidation(t *testing.T) {
	for _, kind := range []crypto.PasswordType{crypto.PasswordTypePlain, crypto.PasswordTypeBcrypt} {
		t.Run(kind.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "password")
			conf := &configuration.AuthorizationSimple{}
			require.NoError(t, conf.SetDefaults())
			conf.Entries = configuration.AuthorizationSimpleEntries{{
				Name: "alice", PasswordFile: crypto.PasswordFile(path), CreatePasswordFileIfAbsentOfType: &kind,
			}}
			require.NoError(t, conf.Validate())
			require.NoFileExists(t, path)

			authorizer, err := NewSimple(t.Context(), "test-flow", conf)
			require.NoError(t, err)
			require.NotNil(t, authorizer)
			first, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NotEmpty(t, first)
			require.NoError(t, crypto.Password(first).Validate())

			_, err = NewSimple(t.Context(), "test-flow", conf)
			require.NoError(t, err)
			second, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, first, second, "an existing credential must not be regenerated")
		})
	}
}

func TestSimpleAuthorizerReloadCannotCreateOrReplaceEmptyPasswordFile(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "empty"}[existing], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "password")
			if existing {
				require.NoError(t, os.WriteFile(path, nil, 0600))
			}
			kind := crypto.PasswordTypePlain
			conf := &configuration.AuthorizationSimple{}
			require.NoError(t, conf.SetDefaults())
			conf.Entries = configuration.AuthorizationSimpleEntries{{
				Name: "alice", PasswordFile: crypto.PasswordFile(path), CreatePasswordFileIfAbsentOfType: &kind,
			}}
			ctx := common.WithProviderBootstrapDisabled(t.Context())
			authorizer, err := NewSimple(ctx, "test-flow", conf)
			require.ErrorIs(t, err, common.ErrProviderBootstrapDisabled)
			require.Nil(t, authorizer)
			if existing {
				raw, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Empty(t, raw)
			} else {
				require.NoFileExists(t, path)
			}
			require.NoError(t, os.WriteFile(path, []byte("plain:provisioned"), 0600))
			authorizer, err = NewSimple(ctx, "test-flow", conf)
			require.NoError(t, err)
			require.NoError(t, authorizer.Close())
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "plain:provisioned", string(raw))
		})
	}
}

func TestSimplePasswordPreparationPreservesInvalidExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	original := []byte("not-a-valid-password")
	require.NoError(t, os.WriteFile(path, original, 0600))
	kind := crypto.PasswordTypePlain
	entry := &configuration.AuthorizationSimpleEntry{
		Name: "alice", PasswordFile: crypto.PasswordFile(path), CreatePasswordFileIfAbsentOfType: &kind,
	}
	err := prepareSimplePasswordFile(entry)
	require.ErrorIs(t, err, crypto.ErrIllegalPasswordFile)
	require.NotContains(t, err.Error(), string(original))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, after)
}

func TestCanceledSimpleAuthorizerPreparationDoesNotCreateCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	kind := crypto.PasswordTypePlain
	conf := &configuration.AuthorizationSimple{}
	require.NoError(t, conf.SetDefaults())
	conf.Entries = configuration.AuthorizationSimpleEntries{{
		Name: "alice", PasswordFile: crypto.PasswordFile(path), CreatePasswordFileIfAbsentOfType: &kind,
	}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	authorizer, err := NewSimple(ctx, "test-flow", conf)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, authorizer)
	require.NoFileExists(t, path)
}
