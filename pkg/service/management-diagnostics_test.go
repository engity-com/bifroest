package service

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestManagementSessionListReportsSkippedCorruptSession(t *testing.T) {
	directory := t.TempDir()
	login, err := bfcrypto.EnsureKeyFile(filepath.Join(directory, "login"), &bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}, nil)
	require.NoError(t, err)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(bfcrypto.MarshalPublicKey(login.PublicKey()))
	})
	configureManagementKeyClient(t, server, directory)
	storage := server.service.Configuration.Session.V.(*configuration.SessionFs).Storage
	id := session.MustNewId()
	corrupt := filepath.Join(storage, "restricted-key", id.String())
	require.NoError(t, os.MkdirAll(corrupt, 0700))
	path := filepath.Join(corrupt, session.FsFileSession)
	require.NoError(t, os.WriteFile(path, []byte("not-json"), 0600))
	client, err := ssh.Dial("tcp", server.address, &ssh.ClientConfig{
		User: server.username, Auth: []ssh.AuthMethod{ssh.PublicKeys(login.ToSsh())},
		HostKeyCallback: ssh.FixedHostKey(server.service.server.HostSigners[0].PublicKey()),
	})
	require.NoError(t, err)
	defer client.Close()
	human, err := client.NewSession()
	require.NoError(t, err)
	var humanDiagnostic bytes.Buffer
	human.Stderr = &humanDiagnostic
	_, err = human.Output("session ls --format=json")
	require.NoError(t, err)
	require.Contains(t, humanDiagnostic.String(), "cannot decode session")
	var output, remoteDiagnostic bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &output, &remoteDiagnostic)
	require.NoError(t, (management.Target{Host: "management-keys"}).Run(ctx, "session", "ls", "--format=json"))
	require.Contains(t, remoteDiagnostic.String(), "cannot decode session")
	require.Contains(t, remoteDiagnostic.String(), id.String())
	var views []model.SessionView
	require.NoError(t, json.Unmarshal(output.Bytes(), &views))
	require.NotEmpty(t, views, "healthy management sessions must still be listed")
	for _, view := range views {
		require.NotEqual(t, id.String(), view.ID)
	}
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "not-json", string(content), "inspection must preserve the corrupt session for operator review")
}
