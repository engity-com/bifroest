package service

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	clibase "github.com/echocat/cli4g"
	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/require"

	appcli "github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestManagementCLISelectsIsolatedSSHConfiguration(t *testing.T) {
	directory := t.TempDir()
	login, err := bfcrypto.EnsureKeyFile(filepath.Join(directory, "login"), &bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}, nil)
	require.NoError(t, err)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(bfcrypto.MarshalPublicKey(login.PublicKey()))
	})
	configureManagementKeyClient(t, server, directory)
	selected := filepath.Join(directory, "ssh_config")
	unsupported := filepath.Join(directory, "unsupported-system-config")
	require.NoError(t, os.WriteFile(unsupported, []byte("Match final\n UserKnownHostsFile must-not-be-used\n"), 0600))
	previous := ssh_config.DefaultUserSettings
	defaults := &ssh_config.UserSettings{}
	defaults.ConfigFinder(func() string { return unsupported })
	ssh_config.DefaultUserSettings = defaults
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	app := appcli.NewApplication[common.SSHConfigOpts](nil, "", nil).MustCreate()
	defer app.Close()
	for _, flags := range [][]string{{"--sshConfig=" + selected}, {"-F", selected}} {
		var output bytes.Buffer
		ctx := common.ContextWithRemoteTarget(t.Context(), management.Target{Host: "management-keys"})
		ctx = clibase.ContextWithStdio(ctx, nil, &output, nil)
		args := append([]string{"flow", "ls", "--format=json"}, flags...)
		require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileRemote}}, args...))
		var flows []model.FlowSummary
		require.NoError(t, json.Unmarshal(output.Bytes(), &flows))
		require.Len(t, flows, 1)
		require.Equal(t, "management", flows[0].Environment)
	}
}
