package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/browserauth"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

const webMaximumRememberAttempts = 64
const webMaximumRememberAttemptsPerPeer = 4

type webBindingReference struct {
	session session.Session
	id      string
}

func (this *webBindingReference) matches(other *webBindingReference) bool {
	return this != nil && other != nil && this.id == other.id && this.session.Flow() == other.session.Flow() && this.session.Id() == other.session.Id()
}

type webRememberAttempt struct {
	scope    webScope
	peer     netip.Addr
	purpose  string
	proof    *browserauth.Challenge
	sess     session.Session
	spec     session.BrowserBindingSpec
	binding  session.BrowserBinding
	parent   *webAccess // Enrollment only; must still be a live primary permission.
	claiming bool       // Protected by webService.mutex; lazy pruning cannot abort a claim.
}

func webRememberAttemptKey(token string) ([32]byte, bool) {
	if len(token) != 48 || !strings.HasPrefix(token, "bwr1.") {
		return [32]byte{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token[5:])
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
}

func (this *webService) rememberIdle() time.Duration {
	if conf := this.service.Configuration.Http; conf != nil && conf.RememberMe.IdleTimeout.Native() > 0 {
		return conf.RememberMe.IdleTimeout.Native()
	}
	return configuration.DefaultHttpRememberMeIdleTimeout.Native()
}

func (this *webService) handleRemember(w http.ResponseWriter, r *http.Request, scope webScope, peer netip.Addr, values map[string]string) {
	if r.URL.Path == webAPI+"remember/prove" {
		this.proveRemember(w, r, scope, peer, values)
		return
	}
	purpose := strings.TrimPrefix(r.URL.Path, webAPI+"remember/")
	attempt := &webRememberAttempt{scope: scope, peer: peer, purpose: purpose}
	var err error
	if purpose == "enroll" {
		if len(values) != 2 {
			webError(w, 400, "invalid enrollment request")
			return
		}
		access, lookupErr := this.lookup(scope, webBearer(r), false)
		if lookupErr != nil {
			webError(w, 401, "web access denied")
			return
		}
		access.mutex.Lock()
		eligible := !access.closed && access.binding == nil && access.credential.Validate() == nil
		access.mutex.Unlock()
		if !eligible {
			webError(w, 403, "primary authentication required for enrollment")
			return
		}
		attempt.parent = access
		attempt.sess = access.auth.FindSession()
		attempt.spec = session.BrowserBindingSpec{Origin: scope.Origin, Slug: scope.Slug, Identity: access.identity, Target: access.target, User: access.user, PublicKey: browserauth.PublicKey(values["publicKey"]), Credential: access.credential}
		if attempt.spec.Validate() != nil {
			webError(w, 400, "invalid browser public key")
			return
		}
		conn, connErr := newWebLoginConnection(r.Context(), r, scope, access.user)
		if connErr != nil {
			webError(w, 400, "invalid request")
			return
		}
		defer conn.Close()
		if err := this.validate(&environmentContext{service: this.service, connection: conn, authorization: access.auth}, access); err != nil {
			webError(w, 401, "web access denied")
			return
		}
	} else {
		if len(values) != 4 || len(r.Header.Values("Authorization")) != 0 {
			webError(w, 400, "invalid binding selector")
			return
		}
		var flow configuration.FlowName
		var id session.Id
		if flow.Set(values["flow"]) != nil || id.Set(values["sessionId"]) != nil {
			webError(w, 400, "invalid binding selector")
			return
		}
		attempt.sess, err = this.service.sessions.FindBy(r.Context(), flow, id, nil)
		if err != nil {
			webError(w, 401, "browser binding denied")
			return
		}
		store, ok := attempt.sess.(session.BrowserBindingSession)
		if !ok {
			webError(w, 503, "browser binding unavailable")
			return
		}
		entries, readErr := store.BrowserBindings(r.Context())
		if readErr != nil {
			webError(w, 401, "browser binding denied")
			return
		}
		found := false
		for _, binding := range entries {
			if binding.ID == values["bindingId"] && binding.Origin == scope.Origin && binding.Slug == scope.Slug {
				attempt.binding = binding
				attempt.spec = binding.BrowserBindingSpec
				found = true
				break
			}
		}
		if !found {
			webError(w, 401, "browser binding denied")
			return
		}
		if purpose == "resume" {
			if attempt.spec.Credential.Validate() != nil || this.service.sessionConnections.isRevoked(attempt.sess) {
				webError(w, 401, "browser binding denied")
				return
			}
			if _, err := store.CheckBrowserBinding(r.Context(), attempt.binding.ID, attempt.binding.Revision, this.rememberIdle()); err != nil {
				webError(w, 401, "browser binding denied")
				return
			}
		}
	}
	if _, ok := attempt.sess.(session.BrowserBindingSession); !ok {
		webError(w, 503, "browser binding unavailable")
		return
	}
	proofContext := browserauth.Context{Purpose: purpose, Origin: scope.Origin, Slug: scope.Slug, Flow: attempt.sess.Flow().String(), SessionID: attempt.sess.Id().String(), Target: string(attempt.spec.Target)}
	if purpose != "enroll" {
		proofContext.BindingID = attempt.binding.ID
		proofContext.Revision = attempt.binding.Revision
	}
	attempt.proof, err = browserauth.NewChallenge(attempt.spec.PublicKey, proofContext)
	if err != nil {
		webError(w, 400, "invalid browser proof request")
		return
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		webError(w, 503, "browser proof unavailable")
		return
	}
	token := "bwr1." + base64.RawURLEncoding.EncodeToString(nonce[:])
	key, _ := webRememberAttemptKey(token)
	this.mutex.Lock()
	this.pruneLocked(time.Now())
	count := 0
	for _, pending := range this.remember {
		if pending.peer == peer {
			count++
		}
	}
	_, collision := this.remember[key]
	if this.ctx.Err() != nil || r.Context().Err() != nil || len(this.remember) >= webMaximumRememberAttempts || count >= webMaximumRememberAttemptsPerPeer || collision {
		this.mutex.Unlock()
		w.Header().Set("Retry-After", "60")
		webError(w, 429, "browser proof limit reached")
		return
	}
	this.remember[key] = attempt
	this.mutex.Unlock()
	webJSONResponse(w, http.StatusAccepted, struct {
		Status       string    `json:"status"`
		AttemptToken string    `json:"attemptToken"`
		Challenge    string    `json:"challenge"`
		ExpiresAt    time.Time `json:"expiresAt"`
	}{"proof-required", token, base64.StdEncoding.EncodeToString(attempt.proof.Bytes()), attempt.proof.ExpiresAt()})
}

func (this *webService) proveRemember(w http.ResponseWriter, r *http.Request, scope webScope, peer netip.Addr, values map[string]string) {
	if len(values) != 2 {
		webError(w, 400, "invalid browser proof reply")
		return
	}
	key, ok := webRememberAttemptKey(webBearer(r))
	if !ok {
		webError(w, 401, "browser proof denied")
		return
	}
	this.mutex.Lock()
	attempt := this.remember[key]
	if attempt == nil || attempt.claiming || attempt.scope != scope || attempt.peer != peer || this.ctx.Err() != nil {
		this.mutex.Unlock()
		webError(w, 401, "browser proof denied")
		return
	}
	attempt.claiming = true
	this.mutex.Unlock()
	defer func() { this.mutex.Lock(); delete(this.remember, key); this.mutex.Unlock() }()
	signature, err := base64.StdEncoding.Strict().DecodeString(values["signature"])
	if err != nil || len(signature) != 64 || base64.StdEncoding.EncodeToString(signature) != values["signature"] {
		_ = attempt.proof.Verify(nil)
		webError(w, 401, "browser proof denied")
		return
	}
	if err := attempt.proof.Verify(signature); err != nil {
		webError(w, 401, "browser proof denied")
		return
	}
	if r.Context().Err() != nil {
		webError(w, 503, "browser proof unavailable")
		return
	}
	if attempt.purpose == "revoke" {
		this.rememberMutex.Lock()
		err := this.revokeWebBinding(&webBindingReference{attempt.sess, attempt.binding.ID})
		this.rememberMutex.Unlock()
		if err != nil {
			webError(w, 503, "browser binding revocation failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if attempt.purpose == "resume" {
		// Expiry/revoke/revision may have changed while the browser signed. Do
		// not refresh OIDC credentials or otherwise reauthorize stale eligibility.
		entry, err := attempt.sess.(session.BrowserBindingSession).CheckBrowserBinding(r.Context(), attempt.binding.ID, attempt.binding.Revision, this.rememberIdle())
		if err != nil || entry.BrowserBindingSpec != attempt.spec {
			webError(w, 401, "browser binding denied")
			return
		}
	} else {
		attempt.parent.mutex.Lock()
		eligible := !attempt.parent.closed && attempt.parent.binding == nil && time.Now().Before(attempt.parent.expires)
		attempt.parent.mutex.Unlock()
		if !eligible {
			webError(w, 401, "primary authentication ended")
			return
		}
	}
	conn, err := newWebLoginConnection(r.Context(), r, scope, attempt.spec.User)
	if err != nil {
		webError(w, 400, "invalid request")
		return
	}
	defer conn.Close()
	auth, err := this.resumeBrowserAuthorization(conn, attempt.sess, attempt.spec)
	if err != nil {
		webError(w, 401, "browser authentication denied")
		return
	}
	status, response, message := this.commitRemember(r.Context(), conn, attempt, auth)
	if message != "" {
		webError(w, status, message)
		return
	}
	webJSONResponse(w, status, response)
}

// Only durable state/grant publication is serialized against linked logout.
// Never hold the global commit mutex or a parent grant mutex while writing an
// HTTP response: a slow client must not stall unrelated binding commits/logout.
func (this *webService) commitRemember(ctx context.Context, conn *webLoginConnection, attempt *webRememberAttempt, auth authorization.Authorization) (int, any, string) {
	this.rememberMutex.Lock()
	defer this.rememberMutex.Unlock()
	if this.ctx.Err() != nil || conn.IsClosed() {
		return http.StatusServiceUnavailable, nil, "browser proof unavailable"
	}
	store := attempt.sess.(session.BrowserBindingSession)
	if err := this.service.recordAuthenticationCompletedFor(ctx, conn, auth, audit.AuthenticationMethodBrowserRememberMe, audit.EventOutcomeSuccess, ""); err != nil {
		return http.StatusServiceUnavailable, nil, "browser authentication unavailable"
	}
	if attempt.purpose == "enroll" {
		parent := attempt.parent
		parent.mutex.Lock()
		defer parent.mutex.Unlock()
		if parent.closed || parent.binding != nil || !time.Now().Before(parent.expires) {
			return http.StatusUnauthorized, nil, "primary authentication ended"
		}
		binding, err := store.CreateBrowserBinding(ctx, attempt.spec, this.rememberIdle())
		if err != nil {
			return http.StatusServiceUnavailable, nil, "browser binding unavailable"
		}
		parent.binding = &webBindingReference{attempt.sess, binding.ID}
		return http.StatusCreated, webRememberBindingResponse(attempt.sess, binding), ""
	}
	binding, err := store.UseBrowserBinding(ctx, attempt.binding.ID, attempt.binding.Revision, this.rememberIdle())
	if err != nil {
		return http.StatusUnauthorized, nil, "browser binding denied"
	}
	base := &environmentContext{service: this.service, connection: conn, authorization: auth}
	token, access, err := this.issue(attempt.scope, base, attempt.spec.Credential, &attempt.spec)
	if err != nil {
		return http.StatusServiceUnavailable, nil, "web access unavailable"
	}
	access.mutex.Lock()
	access.binding = &webBindingReference{attempt.sess, binding.ID}
	access.mutex.Unlock()
	this.service.oidcRefresh.register(attempt.sess)
	return http.StatusOK, this.accessResponse(access, token), ""
}

func webRememberBindingResponse(sess session.Session, binding session.BrowserBinding) any {
	return struct {
		Status    string    `json:"status"`
		Flow      string    `json:"flow"`
		SessionID string    `json:"sessionId"`
		BindingID string    `json:"bindingId"`
		ExpiresAt time.Time `json:"expiresAt"`
	}{"remembered", sess.Flow().String(), sess.Id().String(), binding.ID, binding.ExpiresAt}
}

type webSessionResumeRequest struct {
	authorizeRequest
	sess session.Session
	spec session.BrowserBindingSpec
}

func (this *webSessionResumeRequest) SessionPossessionVerified() bool  { return true }
func (this *webSessionResumeRequest) SessionToResume() session.Session { return this.sess }
func (this *webSessionResumeRequest) ResumeIdentity() authentication.Identity {
	return this.spec.Identity
}
func (this *webSessionResumeRequest) ResumeCredential() authentication.SessionCredential {
	return this.spec.Credential
}
func (this *webSessionResumeRequest) Sessions() session.Repository { return this.service.sessions }

func (this *webService) resumeBrowserAuthorization(conn *webLoginConnection, sess session.Session, spec session.BrowserBindingSpec) (authorization.Authorization, error) {
	resumer, ok := this.service.authorizer.(authorization.SessionResumer)
	if !ok || spec.Credential.Validate() != nil || this.service.sessionConnections.isRevoked(sess) {
		return nil, authorization.ErrSessionResumeDenied
	}
	req := &webSessionResumeRequest{authorizeRequest: authorizeRequest{service: this.service, connection: conn}, sess: sess, spec: spec}
	auth, err := resumer.ResumeSession(req)
	if err != nil {
		return nil, err
	}
	if auth == nil || !auth.IsAuthorized() || auth.FindSession() == nil || auth.Flow() != sess.Flow() || auth.FindSession().Id() != sess.Id() {
		return nil, authorization.ErrSessionResumeDenied
	}
	base := &environmentContext{service: this.service, connection: conn, authorization: auth}
	if err := this.validate(base, &webAccess{auth: auth, identity: spec.Identity, target: spec.Target}); err != nil {
		return nil, err
	}
	return auth, nil
}

// Caller owns rememberMutex: no resumed grant may publish after this durable
// revoke and child snapshot. Close belongs only to this binding, never a session.
func (this *webService) revokeWebBinding(binding *webBindingReference) error {
	store, ok := binding.session.(session.BrowserBindingSession)
	if !ok {
		return fmt.Errorf("browser binding storage unavailable")
	}
	// Use a bounded cleanup context even when the caller disconnected. A logout
	// already admitted must not leave live linked web children solely due to unload.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	persistErr := store.RevokeBrowserBinding(ctx, binding.id)
	this.mutex.Lock()
	var closing []*webAccess
	for key, access := range this.access {
		access.mutex.Lock()
		matches := binding.matches(access.binding)
		access.mutex.Unlock()
		if matches {
			delete(this.access, key)
			closing = append(closing, access)
		}
	}
	this.mutex.Unlock()
	result := persistErr
	for _, access := range closing {
		result = errors.Join(result, access.close())
	}
	return result // Never acknowledge durable logout when persistence failed.
}
