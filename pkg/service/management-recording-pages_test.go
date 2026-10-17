package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	clibase "github.com/echocat/cli4g"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	appcli "github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfconnection "github.com/engity-com/bifroest/pkg/connection"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestManagementRecordingPagesOverIntegratedSSHClient(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			publicKey, privateKey, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			clientSigner, err := gossh.NewSignerFromKey(privateKey)
			require.NoError(t, err)
			sshPublicKey, err := gossh.NewPublicKey(publicKey)
			require.NoError(t, err)
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(string(gossh.MarshalAuthorizedKey(sshPublicKey)))
				parent := filepath.Dir(conf.Session.V.(*configuration.SessionFs).Storage)
				var configured configuration.Auditlog
				require.NoError(t, configured.SetDefaults())
				configured.Name, configured.IdentityFile = "pages", filepath.Join(parent, "page-signing-key")
				configured.Directory = filepath.Join(parent, "page-journal")
				configured.Recording.Enabled = true
				configured.Recording.Directory = filepath.Join(parent, "page-recordings")
				if encrypted {
					encryptionPublic, _, err := ed25519.GenerateKey(nil)
					require.NoError(t, err)
					key, err := gossh.NewPublicKey(encryptionPublic)
					require.NoError(t, err)
					configured.EncryptionPublicKey = bfcrypto.PublicKeys(string(gossh.MarshalAuthorizedKey(key)))
				}
				conf.Auditlogs = append(conf.Auditlogs, configured)
			})
			repository := server.service.recordingRepositories["pages"].native
			var ids []recording.Id
			for i := range 3 {
				var id recording.Id
				require.NoError(t, id.UnmarshalText([]byte(fmt.Sprintf("%08x-0000-4000-8000-000000000000", i+1))))
				ids = append(ids, id)
				started := time.Now().UTC().Truncate(time.Second).Add(-time.Duration(i) * time.Minute)
				connectionID, err := bfconnection.NewId()
				require.NoError(t, err)
				sessionID, err := session.NewId()
				require.NoError(t, err)
				active, err := repository.CreateActive(t.Context(),
					recording.CastHeader{Version: 3, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: started.Unix()},
					recording.CastMetadata{RecordingId: id, ConnectionId: connectionID, SessionId: sessionID, OperationId: uuid.New(),
						Flow: "restricted-key", Task: audit.SessionTaskExec, ProducerId: server.service.recordingRepositories["pages"].producerId, StartedAt: started}, 300)
				require.NoError(t, err)
				status := uint32(0)
				_, err = active.Seal(time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: started.Add(time.Second)}, &status)
				require.NoError(t, err)
			}
			var configured *configuration.Auditlog
			for i := range server.service.Configuration.Auditlogs {
				if server.service.Configuration.Auditlogs[i].Name == "pages" {
					configured = &server.service.Configuration.Auditlogs[i]
				}
			}
			require.NotNil(t, configured)
			suffix := ".bcast"
			if encrypted {
				suffix = ".becast"
			}
			require.NoError(t, os.WriteFile(filepath.Join(configured.Recording.Directory, "sealed", "ffffffff-ffff-4fff-bfff-ffffffffffff"+suffix), []byte("corrupt unselected artifact"), 0600))
			hostKeys, err := server.service.Service.loadHostPrivateKeys()
			require.NoError(t, err)
			hostKey := hostKeys[0].PublicKey().ToSsh()
			directory := t.TempDir()
			identityPath := filepath.Join(directory, "identity")
			block, err := gossh.MarshalPrivateKey(privateKey, "recording-page-test")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(identityPath, pem.EncodeToMemory(block), 0600))
			hostsPath := filepath.Join(directory, "known_hosts")
			require.NoError(t, os.WriteFile(hostsPath, []byte(knownhosts.Line([]string{knownhosts.Normalize(server.address)}, hostKey)+"\n"), 0600))
			host, port, err := net.SplitHostPort(server.address)
			require.NoError(t, err)
			configPath := filepath.Join(directory, "ssh_config")
			require.NoError(t, os.WriteFile(configPath, []byte(fmt.Sprintf(
				"Host recording-pages\n HostName %s\n Port %s\n User %s\n IdentityAgent none\n IdentityFile %s\n UserKnownHostsFile %s\n",
				host, port, server.username, filepath.ToSlash(identityPath), filepath.ToSlash(hostsPath))), 0600))
			previous := ssh_config.DefaultUserSettings
			settings := &ssh_config.UserSettings{}
			settings.ConfigFinder(func() string { return configPath })
			ssh_config.DefaultUserSettings = settings
			t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
			app := appcli.NewApplication[clibase.NoOptions](nil, "", nil).MustCreate()
			t.Cleanup(func() { require.NoError(t, app.Close()) })
			for _, selected := range []string{"json", "yaml", "cbor"} {
				for i := range 2 {
					var output bytes.Buffer
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					ctx = common.ContextWithRemoteTarget(ctx, management.Target{Host: "recording-pages"})
					ctx = clibase.ContextWithStdio(ctx, nil, &output, nil)
					args := []string{"recording", "ls", "pages", "--limit=1", "--after=" + ids[i].String(), "--format=" + selected}
					require.NoError(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileRemote}}, args...))
					var rows []model.RecordingView
					switch selected {
					case "json":
						require.NoError(t, json.Unmarshal(output.Bytes(), &rows))
					case "yaml":
						require.NoError(t, yaml.Unmarshal(output.Bytes(), &rows))
					case "cbor":
						require.NoError(t, cbor.Unmarshal(output.Bytes(), &rows))
					}
					require.Len(t, rows, 1)
					require.Equal(t, ids[i+1].String(), rows[0].ID)
					require.Equal(t, encrypted, rows[0].Encrypted)
					scope := "full"
					if encrypted {
						scope = "outer"
					}
					require.Equal(t, scope, rows[0].VerificationScope)
				}
			}
			client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
				User: server.username, Auth: []gossh.AuthMethod{gossh.PublicKeys(clientSigner)}, HostKeyCallback: gossh.FixedHostKey(hostKey),
				Timeout: 5 * time.Second,
			})
			require.NoError(t, err)
			defer client.Close()
			for _, limit := range []uint{0, recording.MaximumSealedPageSize + 1} {
				query, err := client.NewSession()
				require.NoError(t, err)
				request, err := transport.EncodeWireRequest([]string{"recording", "ls", "pages", "--limit=" + strconv.FormatUint(uint64(limit), 10)})
				require.NoError(t, err)
				query.Stdin = bytes.NewReader(request)
				var stderr bytes.Buffer
				query.Stderr = &stderr
				output, err := query.Output(transport.WireCommand)
				require.Error(t, err)
				require.Empty(t, output)
				require.Contains(t, stderr.String(), "limit must be between")
			}
			query, err := client.NewSession()
			require.NoError(t, err)
			output, err := query.Output("recording ls pages --limit=1 --after=" + ids[2].String())
			require.Error(t, err)
			require.Empty(t, output, "a selected corrupt artifact must not publish metadata")
			query, err = client.NewSession()
			require.NoError(t, err)
			var stderr bytes.Buffer
			query.Stderr = &stderr
			output, err = query.Output("recording ls pages --format=json --limit=2 --after=" + ids[1].String())
			require.Error(t, err)
			require.Contains(t, string(output), ids[2].String())
			require.NotContains(t, string(output), "ffffffff-ffff-4fff-bfff-ffffffffffff")
			require.NotEmpty(t, stderr.String(), "direct SSH streaming errors must reach stderr")
			require.False(t, json.Valid(output), "failed streaming output must remain incomplete")
			var partial bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			ctx = common.ContextWithRemoteTarget(ctx, management.Target{Host: "recording-pages"})
			ctx = clibase.ContextWithStdio(ctx, nil, &partial, nil)
			err = app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileRemote}},
				"recording", "ls", "pages", "--format=json", "--limit=2", "--after="+ids[1].String())
			require.ErrorContains(t, err, "remote recording stream failed")
			require.Contains(t, partial.String(), ids[2].String())
			require.False(t, json.Valid(partial.Bytes()))
		})
	}
}
