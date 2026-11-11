package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

func webAttemptRequest(handler http.Handler, route, token string, values map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(values)
	return webTestRequest(handler, http.MethodPost, "app.example.org", webAPI+"login/"+route, string(body), token)
}
func startWebAttempt(t *testing.T, handler http.Handler, method, user, slug string, key ssh.PublicKey) string {
	t.Helper()
	values := map[string]string{"slug": slug, "user": user}
	if key != nil {
		values["publicKey"] = base64.StdEncoding.EncodeToString(key.Marshal())
	}
	w := webAttemptRequest(handler, method, "", values)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	var pending webLoginPending
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pending))
	require.NotEmpty(t, pending.AttemptToken)
	return pending.AttemptToken
}
func waitWebLoginStep(t *testing.T, handler http.Handler, token, slug string) *webLoginStep {
	t.Helper()
	var step *webLoginStep
	require.Eventually(t, func() bool {
		w := webAttemptRequest(handler, "poll", token, map[string]string{"slug": slug})
		if w.Code != http.StatusOK {
			t.Errorf("waiting for login step: %d %s", w.Code, w.Body.String())
			return true
		}
		var pending webLoginPending
		if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil {
			t.Error(err)
			return true
		}
		step = pending.Step
		return step != nil
	}, 3*time.Second, 25*time.Millisecond)
	require.NotNil(t, step)
	return step
}
func finishWebAttempt(t *testing.T, handler http.Handler, token, slug string) *httptest.ResponseRecorder {
	t.Helper()
	var result *httptest.ResponseRecorder
	require.Eventually(t, func() bool {
		result = webAttemptRequest(handler, "poll", token, map[string]string{"slug": slug})
		if result.Code != http.StatusOK {
			return true
		}
		var value struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(result.Body.Bytes(), &value); err != nil {
			t.Error(err)
			return true
		}
		return value.Status != "pending"
	}, 4*time.Second, 50*time.Millisecond)
	return result
}
func answerWebStep(handler http.Handler, token, slug string, step *webLoginStep, answer string) *httptest.ResponseRecorder {
	values := map[string]string{"slug": slug, "sequence": step.Sequence}
	if step.Kind == "prompt" {
		values["answer"] = answer
	}
	if step.Kind == "public-key" {
		values["signature"] = answer
	}
	return webAttemptRequest(handler, "reply", token, values)
}
func webLoginTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}
func signWebChallenge(t *testing.T, signer ssh.Signer, step *webLoginStep) string {
	t.Helper()
	challenge, err := base64.StdEncoding.DecodeString(step.Challenge)
	require.NoError(t, err)
	signature, err := signer.Sign(rand.Reader, challenge)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(ssh.Marshal(signature))
}
func webSessionCount(t *testing.T, svc *service) int {
	t.Helper()
	count := 0
	require.NoError(t, svc.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	return count
}

func TestWebInteractivePasswordSharesSessionAndCompletesOnlyOnce(t *testing.T) {
	svc, handler, recorder := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Ssh.Enabled = commonBool(false)
	})
	passwordToken := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	step := waitWebLoginStep(t, handler, token, "Work")
	require.Equal(t, "prompt", step.Kind)
	require.False(t, step.Echo)
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted), 1, "a prompt is not an authenticated success")
	w := webAttemptRequest(handler, "reply", token, map[string]string{"slug": "Work", "sequence": "999", "answer": "correct"})
	require.Equal(t, http.StatusConflict, w.Code)
	w = answerWebStep(handler, token, "Work", step, "correct")
	require.Equal(t, http.StatusAccepted, w.Code)
	require.NotContains(t, w.Body.String(), "correct")
	w = answerWebStep(handler, token, "Work", step, "correct")
	require.Equal(t, http.StatusConflict, w.Code)
	accessToken := webTestToken(t, finishWebAttempt(t, handler, token, "Work"))
	one, two := webTestAccess(t, svc, passwordToken, "Work"), webTestAccess(t, svc, accessToken, "Work")
	require.Equal(t, one.auth.FindSession().Id(), two.auth.FindSession().Id())
	w = webAttemptRequest(handler, "poll", token, map[string]string{"slug": "Work"})
	require.Equal(t, http.StatusUnauthorized, w.Code)
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted)
	require.Len(t, events, 2)
	require.Equal(t, audit.AuthenticationMethodKeyboardInteractive, events[1].AuthenticationMethod)
	require.Equal(t, 1, webSessionCount(t, svc))
}

type webInteractionTestAuthorizer struct {
	authorization.CloseableAuthorizer
	run func(authorization.InteractiveRequest) (authorization.Authorization, error)
}

func (this *webInteractionTestAuthorizer) AuthorizeInteractive(req authorization.InteractiveRequest) (authorization.Authorization, error) {
	return this.run(req)
}

func TestWebInteractiveMessagesAndEchoUseBoundedAcknowledgedSteps(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	delegate := svc.authorizer
	svc.authorizer = &webInteractionTestAuthorizer{CloseableAuthorizer: delegate, run: func(req authorization.InteractiveRequest) (authorization.Authorization, error) {
		if err := req.SendInfo("<b>plain information</b>"); err != nil {
			return nil, err
		}
		if err := req.SendError("plain warning"); err != nil {
			return nil, err
		}
		if _, err := req.Prompt("Display only: ", true); err != nil {
			return nil, err
		}
		return delegate.AuthorizeInteractive(req)
	}}
	token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	for _, expected := range []struct {
		kind string
		echo bool
	}{{"info", false}, {"error", false}, {"prompt", true}, {"prompt", false}} {
		step := waitWebLoginStep(t, handler, token, "Work")
		require.Equal(t, expected.kind, step.Kind)
		require.Equal(t, expected.echo, step.Echo)
		if expected.kind == "info" {
			require.Equal(t, "<b>plain information</b>", step.Message)
		}
		require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, "correct").Code)
	}
	webTestToken(t, finishWebAttempt(t, handler, token, "Work"))
}

func TestWebPublicKeyChallengeRequiresProofBeforeAuthorization(t *testing.T) {
	signer := webLoginTestSigner(t)
	svc, handler, recorder := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = crypto.AuthorizedKeys(`no-pty,command="forced",environment="KEY_ORIGIN=trusted" ` + string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	})
	password := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	token := startWebAttempt(t, handler, "public-key", "alice", "Work", signer.PublicKey())
	step := waitWebLoginStep(t, handler, token, "Work")
	require.Equal(t, "public-key", step.Kind)
	require.Equal(t, 1, webSessionCount(t, svc))
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted), 1)
	challenge, err := base64.StdEncoding.DecodeString(step.Challenge)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(challenge), "bifroest-http-public-key-v1\x00"))
	require.Contains(t, string(challenge), `"origin":"https://app.example.org"`)
	require.Contains(t, string(challenge), `"slug":"Work"`)
	require.Contains(t, string(challenge), ssh.FingerprintSHA256(signer.PublicKey()))
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, signWebChallenge(t, signer, step)).Code)
	proof := webTestToken(t, finishWebAttempt(t, handler, token, "Work"))
	access := webTestAccess(t, svc, proof, "Work")
	require.Equal(t, webTestAccess(t, svc, password, "Work").auth.FindSession().Id(), access.auth.FindSession().Id())
	policy := authorization.AuthorizedKeyPolicyOf(access.auth)
	require.NotNil(t, policy)
	require.False(t, policy.PtyAllowed)
	require.Equal(t, "forced", *policy.ForcedCommand)
	require.Equal(t, "trusted", policy.Environment["KEY_ORIGIN"])
	remembered, err := access.auth.FindSession().HasPublicKey(t.Context(), signer.PublicKey())
	require.NoError(t, err)
	require.False(t, remembered, "regular browser proof must not silently opt into SSH key remembering")
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted)
	require.Len(t, events, 2)
	require.Equal(t, audit.AuthenticationMethodPublicKey, events[1].AuthenticationMethod)
}

func TestWebInvalidKeyProofCannotAllocateEvenForNoneAuthorization(t *testing.T) {
	svc, handler, recorder := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V = &configuration.AuthorizationNone{}
	})
	signer, wrong := webLoginTestSigner(t), webLoginTestSigner(t)
	token := startWebAttempt(t, handler, "public-key", "", "Work", signer.PublicKey())
	step := waitWebLoginStep(t, handler, token, "Work")
	require.Zero(t, webSessionCount(t, svc))
	require.Empty(t, svc.web.access)
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, signWebChallenge(t, wrong, step)).Code)
	w := finishWebAttempt(t, handler, token, "Work")
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Zero(t, webSessionCount(t, svc))
	require.Empty(t, svc.web.access)
	require.Empty(t, recorder.eventsSnapshot())
}

func TestWebKeyChallengeReplayAndScopeChangesFailClosed(t *testing.T) {
	signer := webLoginTestSigner(t)
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = crypto.AuthorizedKeys(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	})
	one := startWebAttempt(t, handler, "public-key", "alice", "Work", signer.PublicKey())
	first := waitWebLoginStep(t, handler, one, "Work")
	two := startWebAttempt(t, handler, "public-key", "alice", "Other", signer.PublicKey())
	second := waitWebLoginStep(t, handler, two, "Other")
	require.NotEqual(t, first.Challenge, second.Challenge)
	for _, scope := range []struct{ host, slug string }{{"other.example.org", "Work"}, {"app.example.org:444", "Work"}, {"app.example.org", "Other"}} {
		w := webTestRequest(handler, "POST", scope.host, webAPI+"login/poll", `{"slug":"`+scope.slug+`"}`, one)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}
	w := webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, one)
	require.Equal(t, http.StatusUnauthorized, w.Code, "attempt proof is not web access")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, two, "Other", second, signWebChallenge(t, signer, first)).Code)
	require.Equal(t, http.StatusUnauthorized, finishWebAttempt(t, handler, two, "Other").Code)
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, one, "Work", first, signWebChallenge(t, signer, first)).Code)
	webTestToken(t, finishWebAttempt(t, handler, one, "Work"))
	require.Equal(t, 1, webSessionCount(t, svc))
}

func TestWebAttemptCancellationAndIdleExpiryCannotMintLateAccess(t *testing.T) {
	for _, mode := range []string{"cancel", "idle"} {
		t.Run(mode, func(t *testing.T) {
			svc, handler, recorder := webTestFixture(t)
			token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
			step := waitWebLoginStep(t, handler, token, "Work")
			attempt, err := svc.web.findAttempt(webScope{Origin: "https://app.example.org", Slug: "Work"}, netip.MustParseAddr("127.0.0.1"), token)
			require.NoError(t, err)
			if mode == "cancel" {
				require.Equal(t, http.StatusNoContent, webAttemptRequest(handler, "cancel", token, map[string]string{"slug": "Work"}).Code)
			} else {
				attempt.idle.Reset(time.Millisecond)
			}
			select {
			case <-attempt.done:
			case <-time.After(time.Second):
				t.Fatal("canceled attempt worker did not stop")
			}
			require.Equal(t, http.StatusUnauthorized, answerWebStep(handler, token, "Work", step, "correct").Code)
			require.Zero(t, webSessionCount(t, svc))
			require.Empty(t, svc.web.access)
			require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted))
		})
	}
}

func TestWebAttemptBudgetsAndShutdownRetainSlotsUntilWorkersReturn(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	for range webMaximumAttemptsPerPeer {
		token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
		waitWebLoginStep(t, handler, token, "Work")
	}
	w := webAttemptRequest(handler, "interactive", "", map[string]string{"slug": "Work", "user": "alice"})
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.NoError(t, svc.web.Close())
	require.Empty(t, svc.web.attempts)
	require.Empty(t, svc.web.access)
}

func TestWebCanceledWorkerCannotReleaseItsCapacityEarly(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	delegate := svc.authorizer
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	svc.authorizer = &webInteractionTestAuthorizer{CloseableAuthorizer: delegate, run: func(req authorization.InteractiveRequest) (authorization.Authorization, error) {
		<-req.Context().Done()
		<-release
		return nil, req.Context().Err()
	}}
	for range webMaximumAttemptsPerPeer {
		token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
		require.Equal(t, http.StatusNoContent, webAttemptRequest(handler, "cancel", token, map[string]string{"slug": "Work"}).Code)
	}
	require.Equal(t, http.StatusTooManyRequests, webAttemptRequest(handler, "interactive", "", map[string]string{"slug": "Work", "user": "alice"}).Code)
	thisDone := make(chan error, 1)
	go func() { thisDone <- svc.web.Close() }()
	select {
	case err := <-thisDone:
		t.Fatalf("shutdown abandoned an outstanding worker: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-thisDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not drain canceled workers")
	}
}

func TestWebAttemptGlobalCapacityIsIndependentOfRequestConcurrency(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	for index := range webMaximumAttempts {
		peer := fmt.Sprintf("192.0.2.%d:1234", index/webMaximumAttemptsPerPeer+1)
		wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.RemoteAddr = peer; handler.ServeHTTP(w, r) })
		startWebAttempt(t, wrapped, "interactive", "alice", "Work", nil)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "198.51.100.1:1234"
		handler.ServeHTTP(w, r)
	})
	require.Equal(t, http.StatusTooManyRequests, webAttemptRequest(wrapped, "interactive", "", map[string]string{"slug": "Work", "user": "alice"}).Code)
	require.Len(t, svc.web.attempts, webMaximumAttempts)
	require.NoError(t, svc.web.Close())
}

func TestWebLoginRepliesRejectSecretsAndCrossPeerUse(t *testing.T) {
	_, handler, _ := webTestFixture(t)
	token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	step := waitWebLoginStep(t, handler, token, "Work")
	for _, field := range []string{"privateKey", "passphrase", "user", "publicKey"} {
		w := webAttemptRequest(handler, "reply", token, map[string]string{"slug": "Work", "sequence": step.Sequence, field: "must not be accepted"})
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	otherPeer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "192.0.2.55:1234"
		handler.ServeHTTP(w, r)
	})
	require.Equal(t, http.StatusUnauthorized, answerWebStep(otherPeer, token, "Work", step, "correct").Code)
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, "correct").Code)
	webTestToken(t, finishWebAttempt(t, handler, token, "Work"))
}

func TestWebInteractiveMessageLimitsFailWithoutGrant(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	delegate := svc.authorizer
	svc.authorizer = &webInteractionTestAuthorizer{CloseableAuthorizer: delegate, run: func(req authorization.InteractiveRequest) (authorization.Authorization, error) {
		return nil, req.SendInfo(strings.Repeat("x", webMaximumLoginMessage+1))
	}}
	token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	require.Equal(t, http.StatusServiceUnavailable, finishWebAttempt(t, handler, token, "Work").Code)
	require.Empty(t, svc.web.access)
	require.Zero(t, webSessionCount(t, svc))
}

func TestWebConcurrentPollClaimsOneAuthenticationResult(t *testing.T) {
	svc, handler, recorder := webTestFixture(t)
	token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	step := waitWebLoginStep(t, handler, token, "Work")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, "correct").Code)
	attempt, err := svc.web.findAttempt(webScope{Origin: "https://app.example.org", Slug: "Work"}, netip.MustParseAddr("127.0.0.1"), token)
	require.NoError(t, err)
	select {
	case <-attempt.done:
	case <-time.After(time.Second):
		t.Fatal("login did not complete")
	}
	var group sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 4)
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- webAttemptRequest(handler, "poll", token, map[string]string{"slug": "Work"})
		}()
	}
	group.Wait()
	close(results)
	success := 0
	for w := range results {
		if w.Code == http.StatusOK {
			webTestToken(t, w)
			success++
		} else {
			require.Equal(t, http.StatusUnauthorized, w.Code)
		}
	}
	require.Equal(t, 1, success)
	require.Len(t, svc.web.access, 1)
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted), 1)
}

func TestWebAttemptStrictCompletedAuditFailureMasksCauseAndDoesNotGrant(t *testing.T) {
	svc, handler, recorder := webTestFixture(t)
	recorder.setErrorBeforeRecordForName(audit.EventNameAuthenticationCompleted, errors.New("private diagnostic"))
	token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	step := waitWebLoginStep(t, handler, token, "Work")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, "correct").Code)
	w := finishWebAttempt(t, handler, token, "Work")
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.NotContains(t, w.Body.String(), "private diagnostic")
	require.Empty(t, svc.web.access)
}
