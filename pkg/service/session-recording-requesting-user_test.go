package service

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/recording"
)

func TestNewRecordingCatalogUsesOriginalRequestingUserNotMappedSubject(t *testing.T) {
	const subject = "recording-requesting-user-private-context"
	const requested = "RECORDING-REQUESTING-USER-PRIVATE-CONTEXT"
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			publicKey, err := ssh.NewPublicKey(public)
			require.NoError(t, err)
			fixtureKey, err := bfcrypto.PrivateKeyFromSdk(private)
			require.NoError(t, err)
			fixtureKeys, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{fixtureKey})
			require.NoError(t, err)
			svc, handler, _, managerToken := managementWebFixture(t, func(conf *configuration.Configuration) {
				auth := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
				auth.Entries = append(auth.Entries, configuration.AuthorizationSimpleEntry{Name: subject, Password: bfcrypto.Password("plain:correct")})
				if encrypted {
					conf.Auditlogs[0].EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(publicKey)))
				}
			})
			token := webTestToken(t, webTestPassword(handler, requested, "correct", "Work"))
			actor := webTestAccess(t, svc, token, "Work")
			identity, err := authorization.AuthenticationOf(actor.auth)
			require.NoError(t, err)
			require.Equal(t, subject, identity.Subject)
			require.Equal(t, subject, identity.Principal)
			require.NotEqual(t, requested, identity.Subject)
			code, _, body := managementWebRead(t, handler, token, "flows/list", nil)
			require.Equal(t, 200, code, body)
			repository := svc.recordingRepositories[svc.Configuration.Auditlogs[0].Name].native
			ids, err := repository.ListSealed(t.Context())
			require.NoError(t, err)
			require.Len(t, ids, 1)
			artifact, err := repository.OpenSealed(t.Context(), ids[0])
			require.NoError(t, err)
			fileName := artifact.FileName()
			metadata, err := recording.Inspect(artifact, artifact.Size(), recording.InspectOptions{ExpectedProducerId: artifact.ProducerId()})
			require.NoError(t, err)
			if encrypted {
				require.Nil(t, metadata.Metadata)
				require.Empty(t, artifact.Summary().User)
				var decrypted *recording.CastMetadata
				_, err := recording.VerifyNativeRecordingFull(artifact, artifact.Size(), fixtureKeys, recording.NativeRecordingVerifyOptions{
					ExpectedProducerId: artifact.ProducerId(), VerifiedMetadata: func(value recording.CastMetadata) { decrypted = &value },
				})
				require.NoError(t, err)
				require.NotNil(t, decrypted)
				require.Equal(t, requested, decrypted.User)
				require.Equal(t, actor.auth.FindSession().Id(), decrypted.SessionId)
				require.Equal(t, actor.auth.Flow(), decrypted.Flow)
			} else {
				require.NotNil(t, metadata.Metadata)
				require.Equal(t, requested, metadata.Metadata.User)
				require.Equal(t, requested, artifact.Summary().User)
			}
			require.NoError(t, artifact.Close())
			// The pre-extension fixture intentionally has no requesting user. The
			// catalog must not synthesize one from its flow/session or today's actor.
			legacyID := catalogRecording(t, svc, "default", 100)
			code, result, body := managementWebRead(t, handler, managerToken, "recordings/list", map[string]string{"auditlog": "default", "user": requested})
			require.Equal(t, 200, code, body)
			if encrypted {
				require.Empty(t, result.Recordings.Items)
				require.NotContains(t, body, requested, "even a matching user filter must not query encrypted private context")
			} else {
				require.Len(t, result.Recordings.Items, 1)
				require.Equal(t, ids[0].String(), result.Recordings.Items[0].ID)
				require.Equal(t, requested, result.Recordings.Items[0].User)
				require.Equal(t, actor.auth.FindSession().Id().String(), result.Recordings.Items[0].SessionID)
				require.Equal(t, actor.auth.Flow().String(), result.Recordings.Items[0].Flow)
				require.Empty(t, result.Recordings.Items[0].Target, "requesting user is not a target account")
			}
			code, result, body = managementWebRead(t, handler, managerToken, "recordings/list", map[string]string{"auditlog": "default", "user": subject})
			require.Equal(t, 200, code, body)
			require.Empty(t, result.Recordings.Items, "filter semantics are exact original names, not mapped subjects")
			code, result, body = managementWebRead(t, handler, managerToken, "recordings/list", map[string]string{"auditlog": "default"})
			require.Equal(t, 200, code, body)
			foundLegacy := false
			for _, row := range result.Recordings.Items {
				if row.ID == legacyID.String() {
					foundLegacy = true
					require.Empty(t, row.User)
					encoded, err := json.Marshal(row)
					require.NoError(t, err)
					require.NotContains(t, string(encoded), `"user"`)
				}
				if encrypted {
					require.True(t, row.MetadataUnavailable)
					require.Empty(t, row.User)
					require.Empty(t, row.Flow)
					require.Empty(t, row.SessionID)
				}
			}
			require.True(t, foundLegacy)
			for _, forbidden := range []string{"plain:correct", `"subject"`, `"principal"`, `"password"`, token, managerToken} {
				require.NotContains(t, body, forbidden)
			}
			suffix := ".bcast"
			if encrypted {
				suffix = ".becast"
			}
			require.Equal(t, ids[0].String()+suffix, fileName, "artifact storage naming remains UUID-only")
			if encrypted {
				require.NotContains(t, body, requested)
				require.NotContains(t, body, `"user"`)
			}
			// All live repository/API assertions are complete. Close drains its
			// operations and releases the Windows lock; fixture cleanup is safe
			// because repository Close returns the same result on repeated calls.
			require.NoError(t, repository.Close())
			if encrypted {
				require.NoError(t, filepath.WalkDir(svc.Configuration.Auditlogs[0].Recording.Directory, func(path string, entry fs.DirEntry, walkErr error) error {
					if walkErr != nil || entry.IsDir() {
						return walkErr
					}
					content, err := os.ReadFile(path)
					require.NoError(t, err)
					require.False(t, bytes.Contains(content, []byte(requested)), "no private user sidecar or plaintext envelope: %s", path)
					return nil
				}))
			}
		})
	}
}

type requestingUserPreparationFailureRepository struct {
	*executionTestRepository
	t    *testing.T
	root string
}

func (r *requestingUserPreparationFailureRepository) Ensure(environment.Request) (environment.Environment, error) {
	entries, err := os.ReadDir(filepath.Join(r.root, "recordings", "active"))
	require.NoError(r.t, err)
	require.Len(r.t, entries, 1, "capture must already exist before environment preparation")
	return nil, errors.New("fixture environment preparation failure")
}

func TestRecordingRequestingUserDoesNotMoveCaptureAfterPreparation(t *testing.T) {
	svc, _, root := executionTestFixture(t, func(environment.TerminalTask) (int, error) {
		t.Fatal("failed preparation must not run the task")
		return -1, nil
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	svc.environments = &requestingUserPreparationFailureRepository{svc.environments.(*executionTestRepository), t, root}
	_, err := svc.executeTerminal(conn, transport.stream, true)
	require.ErrorContains(t, err, "fixture environment preparation failure")
	verified := verifyOnlySessionRecording(t, svc, root)
	require.Equal(t, recording.CastStatusIncomplete, verified.Cast.Result.Status)
	require.Equal(t, transport.Remote().User(), verified.Cast.Metadata.User)
}

type recordingRequestingUserTestConnection struct {
	*executionTestTransport
	user string
}

func (c *recordingRequestingUserTestConnection) Remote() bnet.Remote {
	return associationAdapterRemote(c.user)
}

func TestRecordingOmitsUnrepresentableOptionalUserWithoutChangingCaptureOrFailurePolicy(t *testing.T) {
	for _, policy := range []configuration.AuditlogFailurePolicy{configuration.AuditlogFailurePolicyStrict, configuration.AuditlogFailurePolicyBestEffort} {
		t.Run(policy.String(), func(t *testing.T) {
			for _, test := range []struct{ name, user string }{
				{"control", "invalid\nname"}, {"nul", "invalid\x00name"}, {"invalid-utf8", "invalid\xff"}, {"258-byte-utf8", strings.Repeat("é", 129)},
			} {
				t.Run(test.name, func(t *testing.T) {
					// This exercises recording creation, not an authentication-policy
					// bypass. The separate real SSH test covers an allowed long name.
					require.Error(t, (recording.CastMetadata{User: test.user}).ValidateRequestingUser())
					svc, recorder, root := executionTestFixture(t, func(environment.TerminalTask) (int, error) { return 0, nil }, func(conf *configuration.Configuration) {
						conf.Auditlogs[0].FailurePolicy = policy
					})
					transport, auth := newExecutionTestLogin(t, svc, "run")
					connection := &recordingRequestingUserTestConnection{transport, test.user}
					source := &terminalExecutionSource{stream: transport.stream}
					capture, lifecycle, err := svc.beginRecording(&recordingExecution{
						ctx: t.Context(), close: source.Close, capture: source.Capture,
					}, terminalRecordingPty{}, connection, auth.FindSession(), uuid.New(), auth.Flow(), audit.SessionTaskExec)
					require.NoError(t, err)
					require.NotNil(t, capture)
					require.NotNil(t, lifecycle)
					require.Empty(t, lifecycle.metadata.User, "omit the entire optional value, never truncate/sanitize")
					require.Equal(t, test.user, connection.Remote().User(), "the original audit/transport context is untouched")
					_, err = io.WriteString(source.Terminal(), "capture remains enabled")
					require.NoError(t, err)
					require.NoError(t, lifecycle.finish(0, nil, connection))
					verified := verifyOnlySessionRecording(t, svc, root)
					require.Equal(t, recording.CastStatusCompleted, verified.Cast.Result.Status)
					require.Empty(t, verified.Cast.Metadata.User)
					encoded, err := json.Marshal(verified.Cast.Metadata)
					require.NoError(t, err)
					require.NotContains(t, string(encoded), `"user"`, "unrepresentable optional context is absent, not an empty identity claim")
					require.Contains(t, exportOnlySessionRecording(t, svc, root), "capture remains enabled")
					require.Equal(t, policy, svc.Configuration.Auditlogs[0].FailurePolicy)
					require.False(t, svc.auditlogDisabled(svc.Configuration.Auditlogs[0].Name))
					require.False(t, svc.auditlogStates[svc.Configuration.Auditlogs[0].Name].recordingFailed.Load())
					events := recorder.eventsSnapshot()
					require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingStarted), 1)
					require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingCompleted), 1)
					require.Empty(t, auditEventsNamed(events, audit.EventNameSessionRecordingFailed))
				})
			}
		})
	}
}

func TestSSHRecordingPreservesPreviouslyAllowed258ByteRequestingUser(t *testing.T) {
	user := strings.Repeat("é", 129)
	require.Len(t, []byte(user), 258)
	require.Error(t, (recording.CastMetadata{User: user}).ValidateRequestingUser())
	for _, policy := range []configuration.AuditlogFailurePolicy{configuration.AuditlogFailurePolicyStrict, configuration.AuditlogFailurePolicyBestEffort} {
		t.Run(policy.String(), func(t *testing.T) {
			root := t.TempDir()
			observedUser := make(chan string, 1)
			server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, user, "", &authorizedKeysTestEnvironment{
				run: func(task environment.Task) (int, error) {
					observedUser <- task.Connection().Remote().User()
					_, err := io.WriteString(task.SshSession(), "long-name SSH execution captured")
					return 0, err
				},
			}, func(conf *configuration.Configuration) {
				enableSessionRecordingForLifecycleTest(conf, root)
				conf.Auditlogs[0].FailurePolicy = policy
			})
			recorder := &recordingAuditRecorder{}
			flow := server.service.Configuration.Flows[0].Name
			server.service.flowAuditRecorders[flow] = recorder
			client := server.mustDial(t) // Real SSH + unchanged AuthorizationSimple entry.
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			defer sshSession.Close()
			output, err := sshSession.Output("run")
			require.NoError(t, err)
			require.Equal(t, "long-name SSH execution captured", string(output))
			select {
			case original := <-observedUser:
				require.Equal(t, user, original, "the execution still receives the original 258-byte SSH name")
			default:
				t.Fatal("successful SSH execution did not reach the environment")
			}
			requireAuditEventsNamedEventually(t, recorder, audit.EventNameSessionTaskCompleted, 1)
			verified := verifyOnlySessionRecording(t, server.service, root)
			require.Equal(t, recording.CastStatusCompleted, verified.Cast.Result.Status)
			require.Empty(t, verified.Cast.Metadata.User)
			encoded, err := json.Marshal(verified.Cast.Metadata)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), `"user"`)
			require.Contains(t, exportOnlySessionRecording(t, server.service, root), "long-name SSH execution captured")
			require.Equal(t, policy, server.service.Configuration.Auditlogs[0].FailurePolicy)
			require.False(t, server.service.auditlogDisabled(server.service.Configuration.Auditlogs[0].Name))
			require.False(t, server.service.auditlogStates[server.service.Configuration.Auditlogs[0].Name].recordingFailed.Load())
			events := recorder.eventsSnapshot()
			require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingStarted), 1)
			require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingCompleted), 1)
			require.Empty(t, auditEventsNamed(events, audit.EventNameSessionRecordingFailed))
		})
	}
}
