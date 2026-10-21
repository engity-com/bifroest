package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	clibase "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	appcli "github.com/engity-com/bifroest/pkg/cli"
	clicommon "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestManagementSessionControlOverIntegratedAndDirectSSH(t *testing.T) {
	directory := t.TempDir()
	login, err := bfcrypto.EnsureKeyFile(filepath.Join(directory, "login"), &bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}, nil)
	require.NoError(t, err)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(bfcrypto.MarshalPublicKey(login.PublicKey()))
		var workload configuration.Flow
		require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf(`
name: workload
requirement:
  includedRequestingName: ^workload$
authorization:
  type: simple
  entries:
    - name: workload
      authorizedKeys: %q
environment:
  type: dummy
`, bfcrypto.MarshalPublicKey(login.PublicKey()))), &workload))
		conf.Flows = append(conf.Flows, workload)
		conf.Auditlogs[0].Enabled = true
		conf.Auditlogs[0].IdentityFile = filepath.Join(directory, "audit-key")
		conf.Auditlogs[0].Directory = filepath.Join(directory, "audit")
	})
	configureManagementKeyClient(t, server, directory)
	app := appcli.NewApplication[clibase.NoOptions](nil, "", nil).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	run := func(action string, id session.Id, selected string) []byte {
		t.Helper()
		var output, diagnostic bytes.Buffer
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		ctx = clicommon.ContextWithRemoteTarget(ctx, management.Target{Host: "management-keys"})
		ctx = clibase.ContextWithStdio(ctx, nil, &output, &diagnostic)
		require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{clicommon.ProfileRemote}}, "session", action, id.String(), "--format="+selected), diagnostic.String())
		require.Empty(t, diagnostic.String())
		return output.Bytes()
	}
	loginBytes, err := os.ReadFile(filepath.Join(directory, "login"))
	require.NoError(t, err)
	signer, err := gossh.ParsePrivateKey(loginBytes)
	require.NoError(t, err)
	dial := func(user string) *gossh.Client {
		t.Helper()
		client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
			User: user, Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
			HostKeyCallback: gossh.FixedHostKey(server.service.server.HostSigners[0].PublicKey()), Timeout: 5 * time.Second,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })
		if user == "workload" {
			command, err := client.NewSession()
			require.NoError(t, err)
			require.NoError(t, command.Run("seed-session"))
		}
		return client
	}
	queryID := func(client *gossh.Client) session.Id {
		t.Helper()
		command, err := client.NewSession()
		require.NoError(t, err)
		output, err := command.Output("session ls --flow=workload --format=json")
		require.NoError(t, err)
		var entries []model.SessionView
		require.NoError(t, json.Unmarshal(output, &entries))
		require.Len(t, entries, 1)
		var id session.Id
		require.NoError(t, id.UnmarshalText([]byte(entries[0].ID)))
		return id
	}
	admin := dial(server.username)
	first, second := dial("workload"), dial("workload")
	id := queryID(admin)
	var disconnected model.SessionActionResult
	require.NoError(t, json.Unmarshal(run("disconnect", id, "json"), &disconnected))
	require.Equal(t, model.SessionActionResult{ID: id.String(), Flow: "workload", Action: "disconnect"}, disconnected)
	for _, client := range []*gossh.Client{first, second} {
		done := make(chan error, 1)
		go func() { done <- client.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("workload connection remained open")
		}
	}
	// Reconnect with the same identity: disconnect did not revoke the session.
	third := dial("workload")
	require.Equal(t, id, queryID(admin))
	command, err := admin.NewSession()
	require.NoError(t, err)
	output, err := command.Output("session dispose " + id.String() + " --format=json")
	require.NoError(t, err)
	var disposed model.SessionActionResult
	require.NoError(t, json.Unmarshal(output, &disposed))
	require.Equal(t, "dispose", disposed.Action)
	thirdDone := make(chan error, 1)
	go func() { thirdDone <- third.Wait() }()
	select {
	case <-thirdDone:
	case <-time.After(5 * time.Second):
		t.Fatal("disposed session's connection remained open")
	}
	stored, err := server.service.sessions.FindBy(t.Context(), "workload", id, nil)
	require.NoError(t, err)
	info, err := stored.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateDisposed, info.State())
	// Repeat through the integrated client, exercising wire decoding and text rendering.
	require.Contains(t, string(run("dispose", id, "table")), "dispose")
	// Session revocation does not ban the login identity: a new login gets a new session.
	fourth := dial("workload")
	defer fourth.Close()
	newID := queryID(admin)
	require.NotEqual(t, id, newID)
	self, err := admin.NewSession()
	require.NoError(t, err)
	output, err = self.Output("session ls --flow=restricted-key --format=json")
	require.NoError(t, err)
	var callers []model.SessionView
	require.NoError(t, json.Unmarshal(output, &callers))
	require.Len(t, callers, 1)
	for _, action := range []string{"disconnect", "dispose"} {
		self, err := admin.NewSession()
		require.NoError(t, err)
		var diagnostic bytes.Buffer
		self.Stderr = &diagnostic
		output, err = self.Output("session " + action + " " + callers[0].ID)
		require.Error(t, err)
		require.Empty(t, output)
		require.Contains(t, diagnostic.String(), "session executing this management command")
	}
	// Shared auditlog: each action has one start/completion pair, not duplicates.
	verified, err := audit.VerifyJournals(t.Context(), []audit.JournalSource{{
		Name: "default", Directory: filepath.Join(directory, "audit"), ExpectedProducerId: server.service.auditIdentities["default"].ProducerId(), WithSensitive: true,
	}})
	require.NoError(t, err)
	counts := map[string]int{}
	for _, record := range verified.Records() {
		switch record.Event.Name {
		case audit.EventNameSessionDisconnectStarted, audit.EventNameSessionDisconnectCompleted,
			audit.EventNameSessionDisposeStarted, audit.EventNameSessionDisposeCompleted:
			counts[record.Event.Name]++
			require.Equal(t, id.String(), record.Event.SessionId)
			require.Equal(t, "workload", record.Event.Flow)
		}
	}
	for _, phase := range []string{"started", "completed"} {
		require.Equal(t, 1, counts[fmt.Sprintf("session.disconnect.%s", phase)])
		require.Equal(t, 2, counts[fmt.Sprintf("session.dispose.%s", phase)])
	}
}
