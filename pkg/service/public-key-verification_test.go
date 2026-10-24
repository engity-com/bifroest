package service

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestRawPublicKeyCannotAllocateOrRegisterBeforeProof(t *testing.T) {
	for _, kind := range []string{"simple", "none"} {
		t.Run(kind, func(t *testing.T) {
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
				if kind == "none" {
					conf.Flows[0].Authorization.V = &configuration.AuthorizationNone{}
				}
			})
			recorder := &recordingAuditRecorder{}
			server.service.flowAuditRecorders[server.service.Configuration.Flows[0].Name] = recorder
			blocking := &blockingIncomingCertificateSigner{Signer: server.signer, signStarted: make(chan struct{}), releaseSign: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(blocking.releaseSign) }) }
			t.Cleanup(release)
			type result struct {
				client *gossh.Client
				err    error
			}
			done := make(chan result, 1)
			go func() { client, err := dialAuthorizedKeysTestServer(server, blocking); done <- result{client, err} }()
			select {
			case <-blocking.signStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("client did not reach possession proof")
			}
			assertNoPublicKeyProbeSessionState(t, server)
			events := recorder.eventsSnapshot()
			require.Empty(t, auditEventsNamed(events, audit.EventNameAuthenticationCompleted))
			probes := auditEventsNamed(events, audit.EventNameAuthenticationFlowEvaluated)
			require.Len(t, probes, 1)
			require.Equal(t, audit.AuthenticationPhaseCandidate, probes[0].AuthenticationPhase)
			release()
			select {
			case got := <-done:
				require.NoError(t, got.err)
				defer got.client.Close()
				sshSession, err := got.client.NewSession()
				require.NoError(t, err)
				require.NoError(t, sshSession.Run("true"))
			case <-time.After(5 * time.Second):
				t.Fatal("verified login did not finish")
			}
			count := 0
			require.NoError(t, server.service.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
			require.Equal(t, 1, count)
			evaluated := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluated)
			require.Len(t, evaluated, 2)
			require.Equal(t, audit.AuthenticationPhaseVerified, evaluated[1].AuthenticationPhase)
			require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted), 1)
		})
	}
}

func TestRawPublicKeyAuthorizationIsRecheckedAfterProof(t *testing.T) {
	file := filepath.Join(t.TempDir(), "authorized_keys")
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		entry := &conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0]
		require.NoError(t, os.WriteFile(file, []byte(entry.AuthorizedKeys), 0600))
		entry.AuthorizedKeys = ""
		entry.AuthorizedKeysFile = crypto.AuthorizedKeysFile(file)
	})
	blocking := &blockingIncomingCertificateSigner{Signer: server.signer, signStarted: make(chan struct{}), releaseSign: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(blocking.releaseSign) }) }
	t.Cleanup(release)
	done := make(chan error, 1)
	go func() {
		client, err := dialAuthorizedKeysTestServer(server, blocking)
		if client != nil {
			_ = client.Close()
		}
		done <- err
	}()
	select {
	case <-blocking.signStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not reach possession proof")
	}
	assertNoPublicKeyProbeSessionState(t, server)
	require.NoError(t, os.WriteFile(file, []byte("# key revoked while waiting for signature\n"), 0600))
	release()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("rejected login did not finish")
	}
	assertNoPublicKeyProbeSessionState(t, server)
}

type invalidPossessionSigner struct {
	gossh.Signer
	other gossh.Signer
}

func (this invalidPossessionSigner) Sign(random io.Reader, data []byte) (*gossh.Signature, error) {
	return this.other.Sign(random, data)
}

func TestInvalidRawPossessionSignatureLeavesNoSession(t *testing.T) {
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{})
	client, err := dialAuthorizedKeysTestServer(server, invalidPossessionSigner{Signer: server.signer, other: newIncomingCertificateTestSigner(t)})
	if client != nil {
		_ = client.Close()
	}
	require.Error(t, err)
	assertNoPublicKeyProbeSessionState(t, server)
}

func TestRememberedPublicKeyProbeDoesNotTrackAndRechecksDisposal(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = ""
	})
	ctx := t.Context()
	remote := authorizedKeysTestRemote{user: server.username}
	sess, err := server.service.sessions.Create(ctx, server.service.Configuration.Flows[0].Name, remote, nil)
	require.NoError(t, err)
	require.NoError(t, sess.AddPublicKey(ctx, server.signer.PublicKey()))
	_, err = sess.NotifyLastAccess(ctx, remote, session.StateAuthorized)
	require.NoError(t, err)
	blocking := &blockingIncomingCertificateSigner{Signer: server.signer, signStarted: make(chan struct{}), releaseSign: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(blocking.releaseSign) }) }
	t.Cleanup(release)
	done := make(chan error, 1)
	go func() {
		client, err := dialAuthorizedKeysTestServer(server, blocking)
		if client != nil {
			_ = client.Close()
		}
		done <- err
	}()
	select {
	case <-blocking.signStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("remembered key did not reach possession proof")
	}
	assertNoTrackedProbeConnection(t, server)
	_, err = sess.Dispose(ctx)
	require.NoError(t, err)
	release()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("disposed remembered login did not finish")
	}
	assertNoTrackedProbeConnection(t, server)
	count := 0
	require.NoError(t, server.service.sessions.FindAll(ctx, func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Equal(t, 1, count, "failed remembered login must not create a replacement session")
}

func assertNoPublicKeyProbeSessionState(t *testing.T, server *authorizedKeysTestServer) {
	t.Helper()
	count := 0
	require.NoError(t, server.service.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Zero(t, count, "an unsigned probe must not create persistent state")
	assertNoTrackedProbeConnection(t, server)
}

func assertNoTrackedProbeConnection(t *testing.T, server *authorizedKeysTestServer) {
	t.Helper()
	server.service.sessionConnections.mutex.Lock()
	tracked := len(server.service.sessionConnections.connections)
	server.service.sessionConnections.mutex.Unlock()
	require.Zero(t, tracked, "an unsigned probe is not an authenticated connection")
}
