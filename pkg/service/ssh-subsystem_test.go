package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestSshSubsystemProxyRepliesAfterTargetAndStreamsData(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(hostKey)
	require.NoError(t, err)
	targetConfig := &gossh.ServerConfig{PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
		return nil, nil
	}}
	targetConfig.AddHostKey(signer)
	agentRequests := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				server, channels, requests, err := gossh.NewServerConn(conn, targetConfig)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer func() { _ = server.Close() }()
				go gossh.DiscardRequests(requests)
				for incoming := range channels {
					go func(channel gossh.NewChannel) {
						if channel.ChannelType() != "session" {
							_ = channel.Reject(gossh.UnknownChannelType, "unsupported")
							return
						}
						stream, requests, err := channel.Accept()
						if err != nil {
							return
						}
						defer func() { _ = stream.Close() }()
						for request := range requests {
							if request.Type == "auth-agent-req@openssh.com" {
								_ = request.Reply(true, nil)
								agentRequests <- struct{}{}
								continue
							}
							if request.Type != "subsystem" {
								_ = request.Reply(request.Type == "env", nil)
								continue
							}
							var payload struct{ Name string }
							if gossh.Unmarshal(request.Payload, &payload) != nil || payload.Name == "unsupported" {
								_ = request.Reply(false, nil)
								return
							}
							_ = request.Reply(true, nil)
							if payload.Name == "early-eof" {
								_, _ = io.WriteString(stream, "ready\n")
								_, _ = io.WriteString(stream.Stderr(), "target-stderr")
								_ = stream.CloseWrite()
								_, _ = io.Copy(io.Discard, stream)
								_, _ = stream.SendRequest("exit-status", false, gossh.Marshal(&struct{ Status uint32 }{17}))
								return
							}
							if payload.Name == "status-first" {
								_, _ = io.WriteString(stream, "ready\n")
								_, _ = io.WriteString(stream.Stderr(), "target-stderr")
								_, _ = stream.SendRequest("exit-status", false, gossh.Marshal(&struct{ Status uint32 }{17}))
								_ = stream.CloseWrite()
								for range requests {
								}
								return
							}
							if payload.Name == "status-close" {
								_, _ = io.WriteString(stream, "ready\n")
								_, _ = io.WriteString(stream.Stderr(), "target-stderr")
								_, _ = stream.SendRequest("exit-status", false, gossh.Marshal(&struct{ Status uint32 }{17}))
								return
							}
							_, _ = io.Copy(stream, stream)
							_, _ = io.WriteString(stream.Stderr(), "target-stderr")
							_, _ = stream.SendRequest("exit-status", false, gossh.Marshal(&struct{ Status uint32 }{17}))
							if payload.Name == "status-open" {
								_ = stream.CloseWrite()
								for range requests {
								}
							}
							return
						}
					}(incoming)
				}
			}()
		}
	}()

	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		backend := &configuration.EnvironmentSsh{}
		require.NoError(t, backend.SetDefaults())
		backend.Address = template.MustNewString(listener.Addr().String())
		backend.User = template.MustNewString("target-user")
		backend.AcceptAllHostKeys = true // The test target's host key is generated for this test.
		backend.AllowedSubsystems = common.MustNewRegexp("^(sftp|netconf|powershell|status-open|early-eof|status-first|status-close|unsupported)$")
		conf.Flows[0].Environment.V = backend
	})
	recorder := &recordingAuditRecorder{}
	server.service.flowAuditRecorders[server.service.Configuration.Flows[0].Name] = recorder
	client := server.mustDial(t)
	require.NoError(t, agent.ForwardToAgent(client, agent.NewKeyring()))
	for _, name := range []string{"sftp", "netconf", "powershell", "status-open"} {
		t.Run(name, func(t *testing.T) {
			channel, requests, err := client.OpenChannel("session", nil)
			require.NoError(t, err)
			defer func() { _ = channel.Close() }()
			payload := "binary\x00payload " + name
			if name == "powershell" {
				allowed, err := channel.SendRequest("auth-agent-req@openssh.com", true, nil)
				require.NoError(t, err)
				require.True(t, allowed)
			}
			accepted, err := channel.SendRequest("subsystem", true, gossh.Marshal(&struct{ Name string }{name}))
			require.NoError(t, err)
			require.True(t, accepted)
			if name == "powershell" {
				select {
				case <-agentRequests:
				case <-time.After(time.Second):
					t.Fatal("agent forwarding request did not reach target")
				}
				lateAccepted, err := channel.SendRequest("auth-agent-req@openssh.com", true, nil)
				require.NoError(t, err)
				require.False(t, lateAccepted, "agent forwarding requested after subsystem startup was accepted")
			}
			_, err = io.WriteString(channel, payload)
			require.NoError(t, err)
			require.NoError(t, channel.CloseWrite())
			stderrDone := make(chan string, 1)
			go func() {
				stderr, _ := io.ReadAll(channel.Stderr())
				stderrDone <- string(stderr)
			}()
			stdout, err := io.ReadAll(channel)
			require.NoError(t, err)
			require.Equal(t, payload, string(stdout))
			require.Equal(t, "target-stderr", <-stderrDone)
			var exitCodes []uint32
			for request := range requests {
				if request.Type == "exit-status" {
					var status struct{ Code uint32 }
					require.NoError(t, gossh.Unmarshal(request.Payload, &status))
					exitCodes = append(exitCodes, status.Code)
				}
			}
			require.Equal(t, []uint32{17}, exitCodes)
		})
	}
	t.Run("target EOF before client EOF", func(t *testing.T) {
		channel, requests, err := client.OpenChannel("session", nil)
		require.NoError(t, err)
		defer func() { _ = channel.Close() }()
		accepted, err := channel.SendRequest("subsystem", true, gossh.Marshal(&struct{ Name string }{"early-eof"}))
		require.NoError(t, err)
		require.True(t, accepted)
		output := make(chan string, 1)
		go func() {
			data, _ := io.ReadAll(channel)
			output <- string(data)
		}()
		select {
		case data := <-output:
			require.Equal(t, "ready\n", data)
		case <-time.After(3 * time.Second):
			t.Fatal("target EOF did not reach client before client EOF")
		}
		stderr, err := io.ReadAll(channel.Stderr())
		require.NoError(t, err)
		require.Equal(t, "target-stderr", string(stderr))
		require.NoError(t, channel.CloseWrite())
		for range requests {
		}
	})
	for _, name := range []string{"status-first", "status-close"} {
		t.Run(name+" before client EOF", func(t *testing.T) {
			channel, requests, err := client.OpenChannel("session", nil)
			require.NoError(t, err)
			defer func() { _ = channel.Close() }()
			accepted, err := channel.SendRequest("subsystem", true, gossh.Marshal(&struct{ Name string }{name}))
			require.NoError(t, err)
			require.True(t, accepted)
			type output struct {
				stdout, stderr string
				exitCodes      []uint32
			}
			finished := make(chan output, 1)
			go func() {
				stdout, _ := io.ReadAll(channel)
				stderr, _ := io.ReadAll(channel.Stderr())
				result := output{stdout: string(stdout), stderr: string(stderr)}
				for request := range requests {
					if request.Type == "exit-status" {
						var status struct{ Code uint32 }
						if gossh.Unmarshal(request.Payload, &status) == nil {
							result.exitCodes = append(result.exitCodes, status.Code)
						}
					}
				}
				finished <- result
			}()
			select {
			case result := <-finished:
				require.Equal(t, "ready\n", result.stdout)
				require.Equal(t, "target-stderr", result.stderr)
				require.Equal(t, []uint32{17}, result.exitCodes)
			case <-time.After(3 * time.Second):
				t.Fatal("target exit status did not complete while client stdin stayed open")
			}
		})
	}
	denied, deniedRequests, err := client.OpenChannel("session", nil)
	require.NoError(t, err)
	defer func() { _ = denied.Close() }()
	accepted, err := denied.SendRequest("subsystem", true, gossh.Marshal(&struct{ Name string }{"unsupported"}))
	require.NoError(t, err)
	require.False(t, accepted)
	for request := range deniedRequests {
		require.NotEqual(t, "exit-status", request.Type)
	}
	blocked, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, blocked.RequestSubsystem("blocked"))
	_ = blocked.Close()

	require.Eventually(t, func() bool {
		return len(auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted)) == 9
	}, 5*time.Second, 10*time.Millisecond)
	events := recorder.eventsSnapshot()
	started := auditEventsNamed(events, audit.EventNameSessionTaskStarted)
	completed := auditEventsNamed(events, audit.EventNameSessionTaskCompleted)
	require.Len(t, started, 9)
	for _, name := range []string{"sftp", "netconf", "powershell", "status-open", "early-eof", "status-first", "status-close", "unsupported", "blocked"} {
		found := false
		for _, event := range started {
			if event.SessionSubsystem != name {
				continue
			}
			found = true
			if name == "sftp" {
				require.Equal(t, audit.SessionTaskSftp, event.SessionTask)
			} else {
				require.Equal(t, audit.SessionTaskSubsystem, event.SessionTask)
			}
			for _, result := range completed {
				if result.OperationId == event.OperationId {
					require.Equal(t, name, result.SessionSubsystem)
					if name == "unsupported" || name == "blocked" {
						if name == "blocked" {
							require.Equal(t, audit.EventOutcomeDenied, result.Outcome)
							require.Equal(t, audit.EventReasonEnvironmentPolicy, result.Reason)
						} else {
							require.Equal(t, audit.EventOutcomeFailure, result.Outcome)
						}
					} else {
						require.NotNil(t, result.ExitCode)
						require.Equal(t, 17, *result.ExitCode)
					}
				}
			}
		}
		require.True(t, found, "missing audit event for %s", name)
	}
}

func TestNonSshEnvironmentRejectsUnknownSubsystem(t *testing.T) {
	called := false
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{run: func(environment.Task) (int, error) {
		called = true
		return 0, nil
	}})
	client := server.mustDial(t)
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()
	require.Error(t, session.RequestSubsystem("netconf"))
	require.False(t, called)
}

func TestForcedCommandOverridesNamedSubsystem(t *testing.T) {
	type executedTask struct {
		taskType environment.TaskType
		command  string
	}
	executed := make(chan executedTask, 1)
	server := newAuthorizedKeysTestServer(t, `command="forced-command"`, &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		executed <- executedTask{taskType: task.TaskType(), command: task.SshSession().RawCommand()}
		return 0, nil
	}})
	recorder := &recordingAuditRecorder{}
	server.service.flowAuditRecorders[server.service.Configuration.Flows[0].Name] = recorder
	client := server.mustDial(t)
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()
	require.NoError(t, session.RequestSubsystem("netconf"))
	select {
	case actual := <-executed:
		require.Equal(t, executedTask{taskType: environment.TaskTypeShell, command: "forced-command"}, actual)
	case <-time.After(time.Second):
		t.Fatal("forced command was not run")
	}
	require.Eventually(t, func() bool {
		return len(auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted)) == 1
	}, time.Second, 10*time.Millisecond)
	completed := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted)[0]
	require.Equal(t, audit.SessionTaskSubsystem, completed.SessionTask)
	require.Equal(t, "netconf", completed.SessionSubsystem)
}

func TestInvalidSubsystemRequestsDoNotDisableBestEffortAudit(t *testing.T) {
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{})
	flow := server.service.Configuration.Flows[0].Name
	auditlog := server.service.flowAuditlogs[flow]
	server.service.auditlogStates[auditlog].policy = configuration.AuditlogFailurePolicyBestEffort
	recorder := &recordingAuditRecorder{}
	server.service.flowAuditRecorders[flow] = &failurePolicyAuditRecorder{
		service: server.service, auditlog: auditlog, delegate: recorder,
	}
	client := server.mustDial(t)

	for _, test := range []struct {
		name    string
		prepare func(*gossh.Session) error
	}{
		{name: ""},
		{name: strings.Repeat("x", audit.MaxSessionSubsystemBytes+1)},
		{name: string([]byte{0xff})},
		{name: "sftp\x00"},
		{name: "netconf", prepare: func(session *gossh.Session) error { return session.RequestPty("xterm", 24, 80, nil) }},
	} {
		session, err := client.NewSession()
		require.NoError(t, err)
		if test.prepare != nil {
			require.NoError(t, test.prepare(session))
		}
		require.Error(t, session.RequestSubsystem(test.name))
		_ = session.Close()
	}
	require.False(t, server.service.auditlogDisabled(auditlog))

	valid, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, valid.RequestSubsystem("sftp"))
	_ = valid.Close()
	require.Eventually(t, func() bool {
		return len(auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted)) == 1
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, "sftp", auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted)[0].SessionSubsystem)
}

func TestStalledSubsystemInputConnectionCloseAuditReason(t *testing.T) {
	for _, test := range []struct {
		name           string
		normalFirst    bool
		expectedReason string
	}{
		{name: "watchdog closes connection", expectedReason: audit.EventReasonDeadlineExceeded},
		{name: "normal close wins", normalFirst: true, expectedReason: audit.EventReasonDisconnected},
	} {
		t.Run(test.name, func(t *testing.T) {
			connections := make(chan *connection, 1)
			server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
				connections <- task.Connection().(*connection)
				return 0, nil
			}})
			flow := server.service.Configuration.Flows[0].Name
			recorder := &recordingAuditRecorder{}
			server.service.flowAuditRecorders[flow] = recorder
			client := server.mustDial(t)
			session, err := client.NewSession()
			require.NoError(t, err)
			require.NoError(t, session.Run("true"))
			conn := <-connections
			if test.normalFirst {
				require.NoError(t, conn.Close())
			}
			require.NoError(t, conn.CloseStalledSubsystemInput())
			require.Equal(t, !test.normalFirst, conn.stalledSubsystemInput.Load())
			require.Eventually(t, func() bool {
				return len(auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameConnectionClosed)) == 1
			}, time.Second, 10*time.Millisecond)
			closed := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameConnectionClosed)[0]
			require.Equal(t, test.expectedReason, closed.Reason)
		})
	}
}
