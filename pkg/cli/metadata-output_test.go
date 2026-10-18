package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	clibase "github.com/echocat/cli4g"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	bfnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

type metadataOutputRemote struct{}

func (metadataOutputRemote) User() string     { return "alice" }
func (metadataOutputRemote) Host() bfnet.Host { return bfnet.MustNewHost("127.0.0.1") }
func (metadataOutputRemote) String() string   { return "alice@127.0.0.1" }

func TestLocalMetadataCommandsProtectConfiguredFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "configuration.yaml")
	journal, recordings, sessions := filepath.Join(root, "journal"), filepath.Join(root, "recordings"), filepath.Join(root, "sessions")
	key := filepath.Join(root, "signing-key")
	raw, err := yaml.Marshal(map[string]any{
		"auditlog": []map[string]any{{
			"name": "default", "enabled": true, "identityFile": key, "directory": journal,
			"recording": map[string]any{"enabled": true, "directory": recordings},
		}},
		"session": map[string]string{"type": "fs", "storage": sessions},
		"flows": []map[string]any{{
			"name": "local", "authorization": map[string]string{"type": "none"},
			"environment": map[string]string{"type": "dummy"},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromFile(path))
	identity, err := audit.EnsureIdentity(&conf.Auditlogs[0])
	require.NoError(t, err)
	recorder, err := audit.NewRecorder(&conf.Auditlogs[0], identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(t.Context(), audit.Event{Name: "test.metadata", Flow: "local"}))
	require.NoError(t, recorder.Close())
	repository, err := session.NewFsRepository(t.Context(), conf.Session.V.(*configuration.SessionFs))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	created, err := repository.Create(t.Context(), "local", metadataOutputRemote{}, nil)
	require.NoError(t, err)
	id, err := recording.NewId()
	require.NoError(t, err)
	connectionID, err := connection.NewId()
	require.NoError(t, err)
	started := time.Now().UTC().Truncate(time.Second)
	var cast bytes.Buffer
	writer, err := recording.NewNativeRecordingWriter(&cast, identity, nil,
		recording.CastHeader{Version: 3, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: started.Unix()},
		recording.CastMetadata{RecordingId: id, ConnectionId: connectionID, SessionId: created.Id(), OperationId: uuid.New(),
			Flow: "local", Task: audit.SessionTaskExec, ProducerId: identity.ProducerId(), StartedAt: started},
		300, recording.NativeRecordingWriterLimits{})
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Second, recording.OutputStreamStdout, []byte("recorded metadata test\n")))
	status := uint32(0)
	_, err = writer.Seal(2*time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: started.Add(2 * time.Second)}, &status)
	require.NoError(t, err)
	sealed := filepath.Join(recordings, "sealed")
	require.NoError(t, os.MkdirAll(sealed, 0700))
	artifact := filepath.Join(sealed, id.String()+".bcast")
	require.NoError(t, os.WriteFile(artifact, cast.Bytes(), 0600))
	state := filepath.Join(sessions, "keep-session-state")
	require.NoError(t, os.WriteFile(state, []byte("preserve session state"), 0600))
	files := map[string]string{
		"configuration": path, "signing identity": key, "recording": artifact,
		"journal": filepath.Join(journal, identity.ProducerId().String(), "head.cbor"), "session state": state,
	}
	for _, path := range files {
		require.NoError(t, os.Chmod(path, 0600))
	}
	app := NewApplication[clibase.NoOptions](nil, "", nil).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	opts := &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}
	for _, command := range [][]string{
		{"flow", "ls"}, {"flow", "show", "local"},
		{"session", "ls", "--state=all"}, {"session", "show", created.Id().String()},
		{"audit", "ls"}, {"audit", "show", "default"}, {"audit", "events", "default"}, {"audit", "producer-id", "default"},
		{"recording", "ls", "default"}, {"recording", "show", "default", id.String()},
	} {
		t.Run(command[0]+"/"+command[1], func(t *testing.T) {
			args := append(append([]string{}, command...), "--configuration="+path, "--format=json")
			var control, diagnostic bytes.Buffer
			ctx := clibase.ContextWithStdio(t.Context(), nil, &control, &diagnostic)
			require.NoError(t, app.ParseAndExecute(ctx, opts, args...))
			require.NotEmpty(t, control.Bytes(), "the metadata query must be valid before testing output rejection")
			for name, protected := range files {
				for _, alias := range []bool{false, true} {
					label := "direct"
					if alias {
						label = "hardlink"
					}
					t.Run(name+"/"+label, func(t *testing.T) {
						before, err := os.ReadFile(protected)
						require.NoError(t, err)
						destination := protected
						if alias {
							destination = filepath.Join(t.TempDir(), "output-alias")
							if err := os.Link(protected, destination); err != nil {
								t.Skipf("hard links unavailable: %v", err)
							}
						}
						output, err := os.OpenFile(destination, os.O_WRONLY|os.O_APPEND, 0)
						require.NoError(t, err)
						ctx := clibase.ContextWithStdio(t.Context(), nil, output, &diagnostic)
						err = app.ParseAndExecute(ctx, opts, args...)
						require.NoError(t, output.Close())
						after, readErr := os.ReadFile(protected)
						require.NoError(t, readErr)
						require.True(t, bytes.Equal(before, after), "metadata query modified protected file")
						require.ErrorContains(t, err, "must not replace")
					})
				}
			}
		})
	}
}
