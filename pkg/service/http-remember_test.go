package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/session"
)

type rememberTestBinding struct {
	Flow      string    `json:"flow"`
	SessionID string    `json:"sessionId"`
	BindingID string    `json:"bindingId"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type rememberTestChallenge struct {
	AttemptToken string `json:"attemptToken"`
	Challenge    string `json:"challenge"`
}

type rememberTestBlockedWriter struct {
	http.ResponseWriter
	entered, release chan struct{}
	once             sync.Once
}

func (this *rememberTestBlockedWriter) Write(value []byte) (int, error) {
	this.once.Do(func() { close(this.entered) })
	<-this.release
	return this.ResponseWriter.Write(value)
}

func rememberTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key, base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
}
func rememberTestRequest(handler http.Handler, action, token string, fields map[string]string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(fields)
	return webTestRequest(handler, "POST", "app.example.org", webAPI+"remember/"+action, string(raw), token)
}
func rememberTestStart(t *testing.T, handler http.Handler, action, token string, fields map[string]string) rememberTestChallenge {
	t.Helper()
	response := rememberTestRequest(handler, action, token, fields)
	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	var result rememberTestChallenge
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.True(t, strings.HasPrefix(result.AttemptToken, "bwr1."))
	return result
}
func rememberTestSignature(t *testing.T, key *ecdsa.PrivateKey, challenge rememberTestChallenge) string {
	t.Helper()
	payload, err := base64.StdEncoding.Strict().DecodeString(challenge.Challenge)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(payload), "bifroest-browser-remember-v1\x00"))
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return base64.StdEncoding.EncodeToString(signature)
}
func rememberTestProve(t *testing.T, handler http.Handler, challenge rememberTestChallenge, key *ecdsa.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	return rememberTestRequest(handler, "prove", challenge.AttemptToken, map[string]string{"slug": "Work", "signature": rememberTestSignature(t, key, challenge)})
}
func (this rememberTestBinding) selector() map[string]string {
	return map[string]string{"slug": "Work", "flow": this.Flow, "sessionId": this.SessionID, "bindingId": this.BindingID}
}
func rememberTestEnroll(t *testing.T, handler http.Handler, token, public string, key *ecdsa.PrivateKey) rememberTestBinding {
	t.Helper()
	challenge := rememberTestStart(t, handler, "enroll", token, map[string]string{"slug": "Work", "publicKey": public})
	response := rememberTestProve(t, handler, challenge, key)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var binding rememberTestBinding
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &binding))
	require.NotEmpty(t, binding.BindingID)
	return binding
}
func rememberTestResume(t *testing.T, handler http.Handler, binding rememberTestBinding, key *ecdsa.PrivateKey) string {
	t.Helper()
	challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
	return webTestToken(t, rememberTestProve(t, handler, challenge, key))
}

func TestWebRememberExplicitProofAndResumeKeepOneSessionWithoutLeases(t *testing.T) {
	svc, handler, recorder := webTestFixture(t)
	key, public := rememberTestKey(t)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	access := webTestAccess(t, svc, token, "Work")
	store := access.auth.FindSession().(session.BrowserBindingSession)
	before, err := store.BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Empty(t, before)
	require.Equal(t, http.StatusUnauthorized, rememberTestRequest(handler, "enroll", "", map[string]string{"slug": "Work", "publicKey": public}).Code)
	challenge := rememberTestStart(t, handler, "enroll", token, map[string]string{"slug": "Work", "publicKey": public})
	before, err = store.BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Empty(t, before, "no durable enrollment before possession")
	response := rememberTestProve(t, handler, challenge, key)
	require.Equal(t, 201, response.Code, response.Body.String())
	var binding rememberTestBinding
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &binding))
	require.WithinDuration(t, time.Now().Add(6*time.Hour), binding.ExpiresAt, 2*time.Second)
	require.Equal(t, http.StatusUnauthorized, rememberTestProve(t, handler, challenge, key).Code)
	resumed := rememberTestResume(t, handler, binding, key)
	second := webTestAccess(t, svc, resumed, "Work")
	require.Equal(t, access.auth.FindSession().Id(), second.auth.FindSession().Id())
	require.NotEqual(t, token, resumed)
	require.Equal(t, 1, webSessionCount(t, svc))
	require.Equal(t, access.credential, second.credential)
	entries, err := store.BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.EqualValues(t, 2, entries[0].Revision)
	require.False(t, entries[0].ExpiresAt.Before(binding.ExpiresAt))
	info, err := second.auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateNew, info.State())
	require.Empty(t, response.Header().Values("Set-Cookie"))
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	parsed, err := entries[0].PublicKey.Parse()
	require.NoError(t, err)
	sshKey, err := ssh.NewPublicKey(parsed)
	require.NoError(t, err)
	remembered, err := second.auth.FindSession().HasPublicKey(t.Context(), sshKey)
	require.NoError(t, err)
	require.False(t, remembered)
	require.Equal(t, http.StatusForbidden, rememberTestRequest(handler, "enroll", resumed, map[string]string{"slug": "Work", "publicKey": public}).Code, "resumption cannot silently enroll another key")
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted)
	require.Len(t, events, 3)
	require.Equal(t, audit.AuthenticationMethodBrowserRememberMe, events[2].AuthenticationMethod)
}

func TestWebRememberWrongProofScopeReplayAndUntrustedPayloadsFailClosed(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	wrong, _ := rememberTestKey(t)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	challenge := rememberTestStart(t, handler, "enroll", token, map[string]string{"slug": "Work", "publicKey": public})
	require.Equal(t, 401, rememberTestProve(t, handler, challenge, wrong).Code)
	require.Equal(t, 401, rememberTestProve(t, handler, challenge, key).Code, "failed proof is consumed")
	access := webTestAccess(t, svc, token, "Work")
	entries, err := access.auth.FindSession().(session.BrowserBindingSession).BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Empty(t, entries)
	binding := rememberTestEnroll(t, handler, token, public, key)
	for _, mode := range []string{"origin", "port", "slug", "session", "binding"} {
		fields := binding.selector()
		authority := "app.example.org"
		switch mode {
		case "origin":
			authority = "other.example.org"
		case "port":
			authority = "app.example.org:444"
		case "slug":
			fields["slug"] = "Other"
		case "session":
			fields["sessionId"] = session.MustNewId().String()
		case "binding":
			fields["bindingId"] = "bbr1." + strings.Repeat("x", 43)
		}
		raw, _ := json.Marshal(fields)
		response := webTestRequest(handler, "POST", authority, webAPI+"remember/resume", string(raw), "")
		require.Equal(t, 401, response.Code)
	}
	challenge = rememberTestStart(t, handler, "resume", "", binding.selector())
	wrongPeer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(r.Context())
		r.RemoteAddr = "127.0.0.2:54321"
		handler.ServeHTTP(w, r)
	})
	require.Equal(t, 401, rememberTestProve(t, wrongPeer, challenge, key).Code)
	require.Equal(t, 401, rememberTestRequest(handler, "prove", challenge.AttemptToken, map[string]string{"slug": "Other", "signature": rememberTestSignature(t, key, challenge)}).Code)
	require.Equal(t, 200, rememberTestProve(t, handler, challenge, key).Code, "wrong scope does not consume another scope's attempt")
}

func TestWebRememberLogoutRevokesLinkedGrantsButNotSiblingOrSession(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	siblingKey, siblingPublic := rememberTestKey(t)
	primary := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	sibling := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	binding := rememberTestEnroll(t, handler, primary, public, key)
	siblingBinding := rememberTestEnroll(t, handler, sibling, siblingPublic, siblingKey)
	resumed := rememberTestResume(t, handler, binding, key)
	access := webTestAccess(t, svc, resumed, "Work")
	require.Equal(t, 204, webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, resumed).Code)
	for _, token := range []string{primary, resumed} {
		require.Equal(t, 401, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, token).Code)
	}
	require.Equal(t, 200, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, sibling).Code)
	require.Equal(t, 401, rememberTestRequest(handler, "resume", "", binding.selector()).Code)
	require.NotEmpty(t, rememberTestResume(t, handler, siblingBinding, siblingKey))
	info, err := access.auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, session.StateDisposed, info.State())
}

func TestWebRememberLogoutStorageFailureClosesOwnAccessButCannotAcknowledgeDurableRevocation(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	primary := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	binding := rememberTestEnroll(t, handler, primary, public, key)
	path := filepath.Join(svc.Configuration.Session.V.(*configuration.SessionFs).Storage, binding.Flow, binding.SessionID, session.FsFileBrowserBindings)
	valid, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("invalid-private-browser-state"), 0600))
	response := webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, primary)
	require.Equal(t, 503, response.Code)
	require.NotContains(t, response.Body.String(), "invalid-private-browser-state")
	require.Equal(t, 401, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, primary).Code)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "invalid-private-browser-state", string(after), "corrupt state must not be repaired or erased")
	require.NoError(t, os.WriteFile(path, valid, 0600))
}

func TestWebRememberPayloadNeverAcceptsPrivateKeysOrClientVerificationFlags(t *testing.T) {
	_, handler, _ := webTestFixture(t)
	_, public := rememberTestKey(t)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	for _, extra := range []string{"privateKey", "passphrase", "verified", "credential", "identity"} {
		fields := map[string]string{"slug": "Work", "publicKey": public, extra: "must-not-be-accepted"}
		require.Equal(t, 400, rememberTestRequest(handler, "enroll", token, fields).Code)
	}
}

func TestWebRememberExpiryAndStrictAuditCannotRenewOrIssueLateAccess(t *testing.T) {
	for _, mode := range []string{"audit", "expired while signing", "revoked while signing", "parent logout"} {
		t.Run(mode, func(t *testing.T) {
			svc, handler, recorder := webTestFixture(t)
			key, public := rememberTestKey(t)
			primary := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
			access := webTestAccess(t, svc, primary, "Work")
			binding := rememberTestEnroll(t, handler, primary, public, key)
			store := access.auth.FindSession().(session.BrowserBindingSession)
			before, err := store.BrowserBindings(t.Context())
			require.NoError(t, err)
			challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
			switch mode {
			case "audit":
				recorder.setErrorBeforeRecordForName(audit.EventNameAuthenticationCompleted, errors.New("private audit problem"))
			case "expired while signing":
				// The current shorter timeout applies without killing existing access.
				svc.Configuration.Http = &configuration.Http{RememberMe: configuration.HttpRememberMe{IdleTimeout: common.DurationOf(time.Nanosecond)}}
			case "revoked while signing":
				require.NoError(t, svc.sessionConnections.revoke(access.auth.Flow(), access.auth.FindSession().Id()))
			case "parent logout":
				require.Equal(t, 204, webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, primary).Code)
			}
			response := rememberTestProve(t, handler, challenge, key)
			require.NotEqual(t, 200, response.Code)
			require.NotContains(t, response.Body.String(), "bwa1.")
			require.NotContains(t, response.Body.String(), "private audit")
			after, err := store.BrowserBindings(t.Context())
			require.NoError(t, err)
			if len(after) > 0 {
				require.Equal(t, before[0].Revision, after[0].Revision)
			}
		})
	}
}

func TestWebRememberShorterPolicyObservedBeforeProofCannotReviveAfterIncrease(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	primary := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	binding := rememberTestEnroll(t, handler, primary, public, key)
	svc.Configuration.Http = &configuration.Http{RememberMe: configuration.HttpRememberMe{IdleTimeout: common.DurationOf(time.Nanosecond)}}
	require.Equal(t, 401, rememberTestRequest(handler, "resume", "", binding.selector()).Code)
	svc.Configuration.Http.RememberMe.IdleTimeout = common.DurationOf(24 * time.Hour)
	require.Equal(t, 401, rememberTestRequest(handler, "resume", "", binding.selector()).Code)
	require.Equal(t, 200, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, primary).Code, "binding eligibility expiry does not end an authenticated grant")
}

func TestWebRememberConcurrentClaimsAndSeparateRevisionChallengesHaveOneWinner(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	primary := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	binding := rememberTestEnroll(t, handler, primary, public, key)
	one := rememberTestStart(t, handler, "resume", "", binding.selector())
	two := rememberTestStart(t, handler, "resume", "", binding.selector())
	signature := rememberTestSignature(t, key, one)
	var group sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 3)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			responses <- rememberTestRequest(handler, "prove", one.AttemptToken, map[string]string{"slug": "Work", "signature": signature})
		}()
	}
	group.Wait()
	close(responses)
	wins := 0
	for response := range responses {
		if response.Code == 200 {
			wins++
		} else {
			require.Equal(t, 401, response.Code)
		}
	}
	require.Equal(t, 1, wins)
	require.Equal(t, 401, rememberTestProve(t, handler, two, key).Code, "another challenge pinned to the old revision cannot renew twice")
	access := webTestAccess(t, svc, primary, "Work")
	entries, err := access.auth.FindSession().(session.BrowserBindingSession).BrowserBindings(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 2, entries[0].Revision)
}

func TestWebRememberKeyPolicyIsFreshAndRemovedPrimaryKeyCannotResume(t *testing.T) {
	signer := webLoginTestSigner(t)
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = crypto.AuthorizedKeys(`restrict,command="forced",environment="KEY=value" ` + string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	})
	attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", signer.PublicKey())
	step := waitWebLoginStep(t, handler, attempt, "Work")
	require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, signer, step)).Code)
	primary := webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
	key, public := rememberTestKey(t)
	binding := rememberTestEnroll(t, handler, primary, public, key)
	resumed := webTestAccess(t, svc, rememberTestResume(t, handler, binding, key), "Work")
	policy := authorization.AuthorizedKeyPolicyOf(resumed.auth)
	require.NotNil(t, policy)
	require.False(t, policy.PtyAllowed)
	require.Equal(t, "forced", *policy.ForcedCommand)
	require.Equal(t, "value", policy.Environment["KEY"])
	svc.Configuration.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = ""
	challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
	require.Equal(t, 401, rememberTestProve(t, handler, challenge, key).Code)
}

func TestWebRememberAnonymousBindingsCannotSelectAnotherSession(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V = &configuration.AuthorizationNone{}
	})
	one := webTestToken(t, webTestPassword(handler, "", "", "Work"))
	two := webTestToken(t, webTestPassword(handler, "", "", "Work"))
	key, public := rememberTestKey(t)
	binding := rememberTestEnroll(t, handler, one, public, key)
	fields := binding.selector()
	fields["sessionId"] = webTestAccess(t, svc, two, "Work").auth.FindSession().Id().String()
	require.Equal(t, 401, rememberTestRequest(handler, "resume", "", fields).Code)
	resumed := webTestAccess(t, svc, rememberTestResume(t, handler, binding, key), "Work")
	require.Equal(t, webTestAccess(t, svc, one, "Work").auth.FindSession().Id(), resumed.auth.FindSession().Id())
	require.Empty(t, resumed.user)
}

func TestWebRememberActualHttpsResumeExecutesAndLogoutClosesOnlyBindingChildren(t *testing.T) {
	fixture := newWebSocketFixture(t, webSocketWaitTask)
	key, public := rememberTestKey(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), r.Method, "https://app.example.org"+r.URL.Path, r.Body)
		require.NoError(t, err)
		request.Header = r.Header.Clone()
		response, err := fixture.client.Do(request)
		require.NoError(t, err)
		defer response.Body.Close()
		for name, values := range response.Header {
			w.Header()[name] = values
		}
		w.WriteHeader(response.StatusCode)
		_, err = io.Copy(w, response.Body)
		require.NoError(t, err)
	})
	primary := fixture.login(t)
	sibling := fixture.login(t)
	binding := rememberTestEnroll(t, handler, primary, public, key)
	resumed := rememberTestResume(t, handler, binding, key)
	one, two := fixture.dial(t), fixture.dial(t)
	require.NoError(t, one.WriteJSON(webSocketOpen(resumed)))
	requireWebSocketReady(t, one)
	require.NoError(t, two.WriteJSON(webSocketOpen(sibling)))
	requireWebSocketReady(t, two)
	challenge := rememberTestStart(t, handler, "revoke", "", binding.selector())
	require.Equal(t, 204, rememberTestProve(t, handler, challenge, key).Code)
	_, _, err := one.ReadMessage()
	require.Error(t, err)
	require.Equal(t, 200, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, sibling).Code)
	require.NoError(t, two.Close())
	requireWebSocketsDrained(t, fixture.svc)
}

func TestWebRememberSurvivesServiceRestartButEphemeralAccessDoesNot(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	primary := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	binding := rememberTestEnroll(t, handler, primary, public, key)
	require.NoError(t, svc.environments.(*executionTestRepository).shutdown())
	restarted, err := (&Service{Configuration: svc.Configuration, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	restarted.web = newWebService(restarted)
	boundary, err := https.Boundary(configuration.HttpDomains{"app.example.org"}, restarted.web)
	require.NoError(t, err)
	require.Equal(t, 401, webTestRequest(boundary, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, primary).Code)
	resumed := rememberTestResume(t, boundary, binding, key)
	access := webTestAccess(t, restarted, resumed, "Work")
	require.Equal(t, binding.SessionID, access.auth.FindSession().Id().String())
	require.Equal(t, 1, webSessionCount(t, restarted))
}

func TestWebRememberClaimIsProtectedDuringPolicyCheckAndCapacityIsBounded(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	primary := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	binding := rememberTestEnroll(t, handler, primary, public, key)
	challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	svc.environments.(*executionTestRepository).onAccept = func(environment.Context) (bool, error) {
		once.Do(func() { close(entered) })
		<-release
		return true, nil
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	signature := rememberTestSignature(t, key, challenge)
	go func() {
		done <- rememberTestRequest(handler, "prove", challenge.AttemptToken, map[string]string{"slug": "Work", "signature": signature})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("policy check did not start")
	}
	index, _ := webRememberAttemptKey(challenge.AttemptToken)
	svc.web.mutex.Lock()
	svc.web.pruneLocked(time.Now().Add(time.Hour))
	retained := svc.web.remember[index] != nil
	svc.web.mutex.Unlock()
	require.True(t, retained)
	close(release)
	response := <-done
	require.Equal(t, 200, response.Code, response.Body.String())
	for range webMaximumRememberAttemptsPerPeer {
		rememberTestStart(t, handler, "resume", "", binding.selector())
	}
	require.Equal(t, 429, rememberTestRequest(handler, "resume", "", binding.selector()).Code)
	require.NoError(t, svc.web.Close())
	require.Empty(t, svc.web.remember)
}

func TestWebRememberSlowEnrollmentResponseHoldsNeitherCommitNorParentMutex(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	primary := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	parent := webTestAccess(t, svc, primary, "Work")
	challenge := rememberTestStart(t, handler, "enroll", primary, map[string]string{"slug": "Work", "publicKey": public})
	entered, release := make(chan struct{}), make(chan struct{})
	blocked := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(&rememberTestBlockedWriter{ResponseWriter: w, entered: entered, release: release}, r)
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	signature := rememberTestSignature(t, key, challenge)
	go func() {
		done <- rememberTestRequest(blocked, "prove", challenge.AttemptToken, map[string]string{"slug": "Work", "signature": signature})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("enrollment response did not reach writer")
	}
	commitAvailable := svc.web.rememberMutex.TryLock()
	if commitAvailable {
		svc.web.rememberMutex.Unlock()
	}
	parentAvailable := parent.mutex.TryLock()
	if parentAvailable {
		parent.mutex.Unlock()
	}
	close(release)
	response := <-done
	require.Equal(t, 201, response.Code, response.Body.String())
	require.True(t, commitAvailable, "unrelated commits/logout must not wait for a slow HTTP response")
	require.True(t, parentAvailable, "grant lookup/admission must not wait for a slow HTTP response")
}

func TestWebRememberDelegationUsesBindingCertificateNotSessionCreationRights(t *testing.T) {
	authority := webLoginTestSigner(t)
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		settings := &configuration.AuthorizationBifroest{}
		require.NoError(t, settings.SetDefaults())
		settings.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authority.PublicKey()))))
		settings.Audiences = []string{"restricted-key"}
		conf.Flows[0].Authorization.V = settings
	})
	login := func(pty bool) string {
		signer := incomingAssociationDelegation(t, authority, "origin-alice", "alice", pty)
		attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", signer.PublicKey())
		step := waitWebLoginStep(t, handler, attempt, "Work")
		require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, signer, step)).Code)
		return webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
	}
	first := webTestAccess(t, svc, login(true), "Work")
	secondToken := login(false)
	second := webTestAccess(t, svc, secondToken, "Work")
	require.Equal(t, first.auth.FindSession().Id(), second.auth.FindSession().Id())
	key, public := rememberTestKey(t)
	binding := rememberTestEnroll(t, handler, secondToken, public, key)
	resumed := webTestAccess(t, svc, rememberTestResume(t, handler, binding, key), "Work")
	require.False(t, authorization.AuthorizedKeyPolicyOf(resumed.auth).PtyAllowed)
	require.True(t, authorization.AuthorizedKeyPolicyOf(first.auth).PtyAllowed)
}

func TestWebRememberOidcUsesRetainedGrantAndRejectsLostAccess(t *testing.T) {
	svc, handler, provider, _ := webOidcLoginFixture(t)
	attempt := startWebAttempt(t, handler, "interactive", "", "Work", nil)
	step := waitWebLoginStep(t, handler, attempt, "Work")
	require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, "").Code)
	primary := webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
	access := webTestAccess(t, svc, primary, "Work")
	key, public := rememberTestKey(t)
	binding := rememberTestEnroll(t, handler, primary, public, key)
	stored := oidcAssociationStoredToken(t, access.auth.FindSession())
	stored["expiry"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NoError(t, access.auth.FindSession().SetAuthorizationToken(t.Context(), raw))
	provider.release()
	resumed := rememberTestResume(t, handler, binding, key)
	second := webTestAccess(t, svc, resumed, "Work")
	require.Equal(t, access.auth.FindSession().Id(), second.auth.FindSession().Id())
	require.Empty(t, second.user)
	retained := oidcAssociationStoredToken(t, second.auth.FindSession())
	require.Contains(t, retained["refresh_token"], "rotated-refresh-")
	require.EqualValues(t, 1, provider.logins.Load())
	retained["expiry"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	raw, err = json.Marshal(retained)
	require.NoError(t, err)
	require.NoError(t, second.auth.FindSession().SetAuthorizationToken(t.Context(), raw))
	provider.rejectRefresh.Store(true)
	challenge := rememberTestRequest(handler, "resume", "", binding.selector())
	if challenge.Code == 202 {
		var pending rememberTestChallenge
		require.NoError(t, json.Unmarshal(challenge.Body.Bytes(), &pending))
		require.Equal(t, 401, rememberTestProve(t, handler, pending, key).Code)
	} else {
		require.Equal(t, 401, challenge.Code)
	}
	require.Eventually(t, func() bool { return svc.sessionConnections.isRevoked(second.auth.FindSession()) }, time.Second, 10*time.Millisecond)
}
