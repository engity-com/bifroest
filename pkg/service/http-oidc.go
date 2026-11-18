package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
)

const (
	oidcBrowserPrefix    = "/login/"
	oidcMaximumExchanges = 16
	oidcMaximumRecords   = 1024
	// Deliberately omit ambiguous letter/digit pairs such as 0/O and 1/I/L.
	oidcCodeAlphabet = "3479CDFHJKMNPRTUVWXY"
)

type oidcAuthenticationKey struct{}

// One original interactive attempt, including all of its candidate flows.
// Only the transport adapter may publish its final accepted/denied outcome.
type oidcAuthentication struct {
	transactions []*oidcBrowserTransaction
	current      *oidcBrowserTransaction
	finished     bool
}

// This is only a pending-login permission, never a workload/API credential.
// All mutable fields (including oidcAuthentication) use webService.oidcMutex.
type oidcBrowserTransaction struct {
	ctx                                  context.Context
	cancel                               context.CancelFunc
	client                               *authorization.OidcDeviceAuthAuthorizer
	origin, peer, user, comparison, csrf string
	id                                   string
	ssh                                  bool
	phase, reason                        string
	binding                              [32]byte
	state, nonce, verifier               string
	stateKey, callbackDigest             [32]byte
	choices                              []string
	result                               *authorization.OidcCodeResult
	done                                 chan *authorization.OidcCodeResult
	retainUntil                          time.Time
}

type oidcBrowserView struct {
	ID        string   `json:"id"`
	Status    string   `json:"status"`
	SSH       bool     `json:"ssh"`
	Flow      string   `json:"flow"`
	Principal string   `json:"principal,omitempty"`
	Choices   []string `json:"choices,omitempty"`
	CSRF      string   `json:"csrf,omitempty"`
	URL       string   `json:"url,omitempty"`
	Error     string   `json:"error,omitempty"`
}

func oidcRandom() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func oidcValidToken(value string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(value) == 43 && len(raw) == 32
}

func oidcEqual(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func oidcCode() (string, error) {
	var result [2]byte
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(oidcCodeAlphabet))))
		if err != nil {
			return "", err
		}
		result[i] = oidcCodeAlphabet[n.Int64()]
	}
	return string(result[:]), nil
}

func oidcTerminal(tx *oidcBrowserTransaction) bool {
	return tx.phase == "accepted" || tx.phase == "denied" || tx.phase == "expired"
}

func (this *webService) finishOidcLocked(tx *oidcBrowserTransaction, phase, reason string) {
	if oidcTerminal(tx) {
		return
	}
	tx.phase, tx.reason = phase, reason
	tx.retainUntil = time.Now().Add(time.Minute)
	tx.result, tx.choices = nil, nil
	tx.verifier, tx.nonce, tx.state = "", "", ""
	// A simultaneous timeout may win before Login receives its buffered result.
	// Terminal records must not retain that token through the notification queue.
	select {
	case <-tx.done:
	default:
	}
	select {
	case tx.done <- nil:
	default:
	}
	tx.cancel()
}

func (this *webService) pruneOidcLocked() {
	now := time.Now()
	for key, tx := range this.oidcTickets {
		if !oidcTerminal(tx) && oidcTransactionError(tx) != nil {
			this.expireOidcLocked(tx)
		}
		if oidcTerminal(tx) && !now.Before(tx.retainUntil) {
			delete(this.oidcTickets, key)
			delete(this.oidcStates, tx.stateKey)
			if tx.id != "" {
				delete(this.oidcBrowsers, sha256.Sum256([]byte(tx.id)))
			}
		}
	}
}

func (this *webService) expireOidcLocked(tx *oidcBrowserTransaction) {
	phase, reason := "denied", "canceled"
	if oidcTransactionError(tx) == context.DeadlineExceeded {
		phase, reason = "expired", "timeout"
	}
	if this.ctx.Err() != nil {
		phase, reason = "denied", "shutdown"
	}
	this.finishOidcLocked(tx, phase, reason)
}

// Check the absolute deadline too: a busy scheduler may not have delivered the
// context's cancellation yet. Final transport acceptance must still fail closed.
func oidcTransactionError(tx *oidcBrowserTransaction) error {
	if err := tx.ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := tx.ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// Keep final target validation and required audit inside the ORIGINAL login
// budget, including the gap between primary authorization and an HTTP claim.
func (this *webService) oidcCompletionContext(ctx context.Context, attempt *oidcAuthentication) (context.Context, context.CancelFunc) {
	this.oidcMutex.Lock()
	defer this.oidcMutex.Unlock()
	if attempt == nil || len(attempt.transactions) == 0 {
		return ctx, func() {}
	}
	tx := attempt.current
	if tx == nil {
		bounded, cancel := context.WithCancel(ctx)
		cancel()
		return bounded, cancel
	}
	deadline, _ := tx.ctx.Deadline()
	bounded, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(tx.ctx, cancel)
	if attempt.finished || tx.phase != "authorizing" || oidcTransactionError(tx) != nil {
		cancel()
	}
	return bounded, func() { stop(); cancel() }
}

// An accepted result is committed under the same lock as browser expiration.
// Callers MUST check the return value before publishing SSH auth or a new grant;
// cleanup callers may discard it. No slow I/O is performed while holding this lock.
func (this *webService) finishOidcAuthentication(attempt *oidcAuthentication, accepted bool, reason string) bool {
	if attempt == nil {
		return accepted
	}
	this.oidcMutex.Lock()
	defer this.oidcMutex.Unlock()
	if attempt.finished {
		return false
	}
	if accepted && len(attempt.transactions) != 0 {
		tx := attempt.current
		if tx == nil || tx.phase != "authorizing" || oidcTransactionError(tx) != nil {
			accepted = false
			if tx != nil && oidcTransactionError(tx) != nil {
				this.expireOidcLocked(tx)
			}
		}
	}
	attempt.finished = true
	phase := "denied"
	if accepted {
		phase, reason = "accepted", ""
	}
	for _, tx := range attempt.transactions {
		if oidcTransactionError(tx) == context.DeadlineExceeded {
			this.expireOidcLocked(tx)
		}
		this.finishOidcLocked(tx, phase, reason)
	}
	attempt.transactions = nil
	attempt.current = nil
	return accepted
}

func (this *webService) Login(req authorization.InteractiveRequest, client *authorization.OidcDeviceAuthAuthorizer) (*oauth2.Token, error) {
	conf := client.CodeConfiguration()
	attempt, _ := req.Context().Value(oidcAuthenticationKey{}).(*oidcAuthentication)
	if conf == nil || attempt == nil {
		return nil, fmt.Errorf("OIDC original login attempt unavailable")
	}
	selection, err := bconn.SelectionOf(req)
	if err != nil {
		return nil, err
	}
	origin := conf.Origin()
	if selection.Transport == bconn.TransportHttp {
		conn, ok := req.Connection().(*webLoginConnection)
		if !ok || conn.scope.Origin != origin {
			return nil, fmt.Errorf("OIDC login requires its configured HTTPS origin")
		}
	}
	this.oidcMutex.Lock()
	this.pruneOidcLocked()
	// A denied candidate may fall through to another flow using the SAME OIDC
	// configuration. Keep its verified primary result, not a second SSO login.
	for _, previous := range attempt.transactions {
		if previous.phase == "authorizing" && previous.result != nil {
			// Display-only SSH wording must not force another SSO/approval when
			// otherwise equivalent candidate flows share the verified identity.
			equivalent := *previous.client.CodeConfiguration()
			equivalent.Ssh.LoginMessage = conf.Ssh.LoginMessage
			if !equivalent.IsEqualTo(*conf) {
				continue
			}
			token := previous.result.Token
			attempt.current = previous
			this.oidcMutex.Unlock()
			return token, nil
		}
	}
	this.oidcMutex.Unlock()
	ticket, err := oidcRandom()
	if err != nil {
		return nil, err
	}
	comparison, err := oidcCode()
	if err != nil {
		return nil, err
	}
	parent := req.Context()
	if lifetime, ok := req.Connection().(bconn.LifetimeAware); ok {
		parent = lifetime.Lifetime()
	}
	deadline := time.Now().Add(conf.LoginTimeout.Native())
	if earlier, ok := req.Context().Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	stopShutdown := context.AfterFunc(this.ctx, cancel)
	remote := req.Connection().Remote()
	tx := &oidcBrowserTransaction{ctx: ctx, cancel: cancel, client: client, origin: origin, peer: remote.Host().String(), user: remote.User(), comparison: comparison, ssh: selection.Transport == bconn.TransportSsh, phase: "created", done: make(chan *authorization.OidcCodeResult, 1)}
	context.AfterFunc(ctx, func() {
		stopShutdown()
		this.oidcMutex.Lock()
		defer this.oidcMutex.Unlock()
		this.expireOidcLocked(tx)
	})
	this.oidcMutex.Lock()
	if this.oidcTickets == nil {
		this.oidcTickets = make(map[[32]byte]*oidcBrowserTransaction)
		this.oidcStates = make(map[[32]byte]*oidcBrowserTransaction)
		this.oidcBrowsers = make(map[[32]byte]*oidcBrowserTransaction)
	}
	active, peerCount := 0, 0
	usedCodes := make(map[string]bool)
	for _, pending := range this.oidcTickets {
		if !oidcTerminal(pending) {
			active++
			usedCodes[pending.comparison] = true
			if pending.peer == tx.peer {
				peerCount++
			}
		}
	}
	for usedCodes[tx.comparison] && err == nil {
		tx.comparison, err = oidcCode()
	}
	key := sha256.Sum256([]byte(ticket))
	if err != nil || attempt.finished || this.ctx.Err() != nil || ctx.Err() != nil || active >= webMaximumAttempts || peerCount >= webMaximumAttemptsPerPeer || len(this.oidcTickets) >= oidcMaximumRecords || this.oidcTickets[key] != nil {
		this.oidcMutex.Unlock()
		cancel()
		return nil, fmt.Errorf("OIDC login capacity unavailable")
	}
	this.oidcTickets[key] = tx
	attempt.transactions = append(attempt.transactions, tx)
	attempt.current = tx
	this.oidcMutex.Unlock()
	message := "Open the following URL in your browser to login: " + origin + oidcBrowserPrefix + "#start/" + ticket
	if tx.ssh {
		message, err = authorization.RenderOidcSshLoginMessage(req, conf.Ssh.LoginMessage, origin+oidcBrowserPrefix+"#start/"+ticket, tx.comparison, true)
		if err != nil {
			this.oidcMutex.Lock()
			this.finishOidcLocked(tx, "denied", "unavailable")
			this.oidcMutex.Unlock()
			return nil, err
		}
	}
	if bounded, ok := req.(interface {
		SendOidcInfo(context.Context, string) error
	}); ok {
		err = bounded.SendOidcInfo(ctx, message)
	} else {
		err = req.SendInfo(message)
	}
	if err != nil {
		this.oidcMutex.Lock()
		this.finishOidcLocked(tx, "denied", "disconnected")
		this.oidcMutex.Unlock()
		return nil, fmt.Errorf("OIDC login client disconnected")
	}
	select {
	case <-ctx.Done():
		this.oidcMutex.Lock()
		this.expireOidcLocked(tx)
		this.oidcMutex.Unlock()
		return nil, fmt.Errorf("OIDC login expired")
	case <-req.Context().Done():
		this.oidcMutex.Lock()
		this.finishOidcLocked(tx, "expired", "timeout")
		this.oidcMutex.Unlock()
		return nil, fmt.Errorf("OIDC login expired")
	case <-this.ctx.Done():
		this.oidcMutex.Lock()
		this.finishOidcLocked(tx, "denied", "shutdown")
		this.oidcMutex.Unlock()
		return nil, fmt.Errorf("OIDC login stopped")
	case result := <-tx.done:
		if result != nil && req.Context().Err() == nil {
			return result.Token, nil
		}
		this.oidcMutex.Lock()
		reason := tx.reason
		this.oidcMutex.Unlock()
		if reason == "code_mismatch" || reason == "user_denied" {
			if bounded, ok := req.(interface {
				SendOidcInfo(context.Context, string) error
			}); ok {
				messageCtx, stop := context.WithTimeout(req.Context(), 2*time.Second)
				_ = bounded.SendOidcInfo(messageCtx, "OIDC login aborted ("+reason+").")
				stop()
			}
		}
		return nil, fmt.Errorf("OIDC login denied")
	}
}

func oidcCookieName(id string) string { return "__Host-bifroest-oidc-" + id }

func oidcCookie(w http.ResponseWriter, id, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookieName(id), Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: expires})
}

func oidcBound(r *http.Request, tx *oidcBrowserTransaction) bool {
	count, value := 0, ""
	for _, cookie := range r.Cookies() {
		if cookie.Name == oidcCookieName(tx.id) {
			count++
			value = cookie.Value
		}
	}
	return tx.id != "" && count == 1 && oidcValidToken(value) && sha256.Sum256([]byte(value)) == tx.binding
}

// Documents never start/consume/exchange a login. Even a callback only loads
// the same small SPA; its JavaScript makes a same-origin, cookie-bound API POST.
func (this *webService) serveOidc(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/login" && r.URL.Path != "/login/" && r.URL.Path != configuration.OidcCallbackPath {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != configuration.OidcCallbackPath && (r.URL.RawQuery != "" || r.URL.ForceQuery) || len(r.URL.RawQuery) > 8<<10 {
		webError(w, 400, "invalid login URL")
		return
	}
	release, ok := this.admitAsset(w, r)
	if !ok {
		return
	}
	defer release()
	if !this.serveBrowserDocument(w, r, true) {
		webError(w, 503, "login application unavailable")
	}
}

func (this *webService) oidcViewLocked(tx *oidcBrowserTransaction) oidcBrowserView {
	view := oidcBrowserView{ID: tx.id, Status: tx.phase, SSH: tx.ssh, Flow: string(tx.client.CodeFlow()), Error: tx.reason}
	if tx.phase == "approval" && tx.result != nil {
		view.Principal, view.Choices, view.CSRF = tx.result.Identity.Principal, append([]string(nil), tx.choices...), tx.csrf
	}
	return view
}

func (this *webService) serveOidcAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		webError(w, 405, "POST required")
		return
	}
	action := strings.TrimPrefix(r.URL.Path, webAPI+"oidc/")
	fields := map[string][]string{"start": {"ticket"}, "status": {"id"}, "callback": {"query"}, "approve": {"id", "csrf", "code"}, "deny": {"id", "csrf"}}
	allowed, exists := fields[action]
	if !exists {
		http.NotFound(w, r)
		return
	}
	peer, err := webPeer(r)
	if err != nil {
		webError(w, 400, "invalid peer")
		return
	}
	release, admitted := this.admit(peer, action == "start")
	if !admitted {
		webError(w, 429, "login capacity unavailable")
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(this.ctx, cancel)
	defer stop()
	r = r.WithContext(ctx)
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Second))
	values, err := webJSONObject(w, r, false, allowed...)
	if err != nil || len(values) != len(allowed) {
		webError(w, 400, "invalid login request")
		return
	}
	if action == "callback" {
		this.oidcCallback(w, r, values["query"])
		return
	}
	scope, err := requestWebScope(r, "")
	if err != nil {
		webError(w, 400, "invalid origin")
		return
	}
	this.oidcMutex.Lock()
	this.pruneOidcLocked()
	defer this.oidcMutex.Unlock()
	var tx *oidcBrowserTransaction
	if action == "start" {
		if oidcValidToken(values["ticket"]) {
			tx = this.oidcTickets[sha256.Sum256([]byte(values["ticket"]))]
		}
	} else if oidcValidToken(values["id"]) {
		tx = this.oidcBrowsers[sha256.Sum256([]byte(values["id"]))]
	}
	if tx == nil || tx.origin != scope.Origin {
		webError(w, 401, "login unavailable")
		return
	}
	if action == "start" && tx.phase == "created" {
		id, e1 := oidcRandom()
		binding, e2 := oidcRandom()
		state, e3 := oidcRandom()
		nonce, e4 := oidcRandom()
		verifier, e5 := oidcRandom()
		csrf, e6 := oidcRandom()
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || this.oidcBrowsers[sha256.Sum256([]byte(id))] != nil || this.oidcStates[sha256.Sum256([]byte(state))] != nil {
			webError(w, 503, "login unavailable")
			return
		}
		tx.id, tx.binding, tx.state, tx.nonce, tx.verifier, tx.csrf, tx.phase = id, sha256.Sum256([]byte(binding)), state, nonce, verifier, csrf, "redirected"
		tx.stateKey = sha256.Sum256([]byte(state))
		this.oidcBrowsers[sha256.Sum256([]byte(id))], this.oidcStates[sha256.Sum256([]byte(state))] = tx, tx
		expires, _ := tx.ctx.Deadline()
		oidcCookie(w, id, binding, expires.Add(time.Minute))
		view := this.oidcViewLocked(tx)
		view.URL = tx.client.CodeAuthorizationURL(state, nonce, verifier)
		webJSONResponse(w, 200, view)
		return
	}
	if !oidcBound(r, tx) {
		webError(w, 401, "login unavailable")
		return
	}
	if action == "start" || action == "status" {
		view := this.oidcViewLocked(tx)
		if tx.phase == "redirected" {
			view.URL = tx.client.CodeAuthorizationURL(tx.state, tx.nonce, tx.verifier)
		}
		webJSONResponse(w, 200, view)
		return
	}
	if tx.phase != "approval" || tx.result == nil || !oidcEqual(values["csrf"], tx.csrf) {
		webError(w, 409, "login decision unavailable")
		return
	}
	if action == "deny" || !oidcEqual(values["code"], tx.comparison) {
		reason := "user_denied"
		if action == "approve" {
			reason = "code_mismatch"
		}
		this.finishOidcLocked(tx, "denied", reason)
	} else {
		tx.phase = "authorizing"
		tx.choices = nil
		tx.done <- tx.result
	}
	webJSONResponse(w, 200, this.oidcViewLocked(tx))
}

func (this *webService) oidcCallback(w http.ResponseWriter, r *http.Request, raw string) {
	if len(raw) > 8<<10 {
		webError(w, 400, "invalid callback")
		return
	}
	query, err := url.ParseQuery(strings.TrimPrefix(raw, "?"))
	if err != nil {
		webError(w, 400, "invalid callback")
		return
	}
	for name, values := range query {
		if len(values) != 1 || len(values[0]) > 4096 {
			webError(w, 400, "invalid callback")
			return
		}
		switch name {
		case "code", "state", "iss", "session_state", "error", "error_description", "error_uri":
		default:
			webError(w, 400, "invalid callback")
			return
		}
	}
	state := query.Get("state")
	_, hasCode := query["code"]
	_, hasError := query["error"]
	_, hasDescription := query["error_description"]
	_, hasURI := query["error_uri"]
	if !oidcValidToken(state) || hasCode == hasError || hasCode && (query.Get("code") == "" || hasDescription || hasURI) || hasError && query.Get("error") == "" {
		webError(w, 400, "invalid callback")
		return
	}
	scope, scopeErr := requestWebScope(r, "")
	key := sha256.Sum256([]byte(state))
	this.oidcMutex.Lock()
	this.pruneOidcLocked()
	tx := this.oidcStates[key]
	_, hasIssuer := query["iss"]
	if tx == nil || !oidcBound(r, tx) || scopeErr != nil || tx.origin != scope.Origin || hasIssuer && query.Get("iss") != tx.client.CodeIssuer() {
		this.oidcMutex.Unlock()
		webError(w, 401, "callback denied")
		return
	}
	// An identical callback may be retried by its bound browser after a lost
	// response. It only reads the outcome; the provider code is exchanged once.
	digest := sha256.Sum256([]byte(query.Encode()))
	if tx.phase != "redirected" {
		if tx.callbackDigest != digest {
			this.oidcMutex.Unlock()
			webError(w, 401, "callback denied")
			return
		}
		view := this.oidcViewLocked(tx)
		this.oidcMutex.Unlock()
		webJSONResponse(w, 200, view)
		return
	}
	if this.oidcExchanges >= oidcMaximumExchanges {
		this.oidcMutex.Unlock()
		webError(w, 429, "provider capacity unavailable")
		return
	}
	this.oidcExchanges++
	tx.callbackDigest = digest
	tx.phase = "exchanging"
	verifier, nonce := tx.verifier, tx.nonce
	tx.verifier, tx.nonce, tx.state = "", "", ""
	this.oidcMutex.Unlock()
	var result *authorization.OidcCodeResult
	if !hasError {
		ctx, cancel := context.WithTimeout(tx.ctx, 15*time.Second)
		result, err = tx.client.ExchangeCode(ctx, query.Get("code"), verifier, nonce)
		cancel()
	}
	this.oidcMutex.Lock()
	defer this.oidcMutex.Unlock()
	this.oidcExchanges--
	if oidcTerminal(tx) || tx.ctx.Err() != nil || err != nil || result == nil {
		this.finishOidcLocked(tx, "denied", "identity_failed")
		webJSONResponse(w, 200, this.oidcViewLocked(tx))
		return
	}
	tx.result = result
	if tx.ssh {
		tx.choices = []string{tx.comparison}
		for len(tx.choices) < 3 {
			candidate, codeErr := oidcCode()
			if codeErr != nil {
				this.finishOidcLocked(tx, "denied", "unavailable")
				webJSONResponse(w, 200, this.oidcViewLocked(tx))
				return
			}
			unique := true
			for _, existing := range tx.choices {
				unique = unique && candidate != existing
			}
			if unique {
				tx.choices = append(tx.choices, candidate)
			}
		}
		for i := len(tx.choices) - 1; i > 0; i-- {
			n, randomErr := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
			if randomErr != nil {
				this.finishOidcLocked(tx, "denied", "unavailable")
				webJSONResponse(w, 200, this.oidcViewLocked(tx))
				return
			}
			j := int(n.Int64())
			tx.choices[i], tx.choices[j] = tx.choices[j], tx.choices[i]
		}
		tx.phase = "approval"
	} else {
		tx.phase = "authorizing"
		tx.done <- result
	}
	webJSONResponse(w, 200, this.oidcViewLocked(tx))
}
