package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

const (
	webAPI                      = "/_bifroest/api/v1/"
	webMaximumAccess            = 1024
	webMaximumPeers             = 1024
	webMaximumWorkers           = 64
	webMaximumWorkersPerPeer    = 4
	webMaximumLoginsPerMinute   = 12
	webMaximumRequestsPerMinute = 120
	webLoginBodyLimit           = 16 << 10
)

type webPeerBudget struct {
	since                    time.Time
	requests, logins, active int
}

type webService struct {
	service         *service
	ctx             context.Context
	cancel          context.CancelFunc
	operations      *connectionLifecycle
	mutex           sync.Mutex
	peers           map[netip.Addr]*webPeerBudget
	active          int
	access          map[[32]byte]*webAccess
	attempts        map[[32]byte]*webLoginAttempt
	loginWorkers    *connectionLifecycle
	sockets         int
	socketPeers     map[netip.Addr]int
	terminalTimings webTerminalTimings
	closeOnce       sync.Once
	closeErr        error
	remember        map[[32]byte]*webRememberAttempt
	rememberMutex   sync.Mutex // Durable binding commit/logout and linked-grant publication.
}

func newWebService(svc *service) *webService {
	ctx, cancel := context.WithCancel(context.Background())
	return &webService{service: svc, ctx: ctx, cancel: cancel, operations: newConnectionLifecycle(), loginWorkers: newConnectionLifecycle(), peers: make(map[netip.Addr]*webPeerBudget), access: make(map[[32]byte]*webAccess), attempts: make(map[[32]byte]*webLoginAttempt), socketPeers: make(map[netip.Addr]int), terminalTimings: defaultWebTerminalTimings(), remember: make(map[[32]byte]*webRememberAttempt)}
}

// Lazy, bounded cleanup requires no per-token goroutines. Expired permissions
// with running children remain addressable for logout, never for new access.
func (this *webService) pruneLocked(now time.Time) {
	for key, attempt := range this.remember {
		if !attempt.claiming && !now.Before(attempt.proof.ExpiresAt()) {
			delete(this.remember, key)
		}
	}
	for key, attempt := range this.attempts {
		attempt.mutex.Lock()
		expired := !attempt.claiming && (attempt.consumed || attempt.conn.IsClosed())
		attempt.mutex.Unlock()
		if expired {
			select {
			case <-attempt.done:
				attempt.stop()
				delete(this.attempts, key)
			default:
			}
		}
	}
	for peer, budget := range this.peers {
		if budget.active == 0 && now.Sub(budget.since) >= time.Minute {
			delete(this.peers, peer)
		}
	}
	for key, access := range this.access {
		access.mutex.Lock()
		remove := access.closed || !now.Before(access.expires) && len(access.children) == 0
		access.mutex.Unlock()
		if remove {
			delete(this.access, key)
		}
	}
}

func (this *webService) admit(peer netip.Addr, login bool) (func(), bool) {
	release, ok := this.operations.register()
	if !ok {
		return nil, false
	}
	this.mutex.Lock()
	now := time.Now()
	this.pruneLocked(now)
	budget := this.peers[peer]
	if budget == nil && len(this.peers) < webMaximumPeers {
		budget = &webPeerBudget{since: now}
		this.peers[peer] = budget
	}
	if budget != nil && now.Sub(budget.since) >= time.Minute {
		budget.since = now
		budget.requests = 0
		budget.logins = 0
	}
	if budget == nil || this.active >= webMaximumWorkers || budget.active >= webMaximumWorkersPerPeer || budget.requests >= webMaximumRequestsPerMinute || login && (budget.logins >= webMaximumLoginsPerMinute || len(this.access)+len(this.attempts)+len(this.remember)+this.active >= webMaximumAccess) || this.ctx.Err() != nil {
		this.mutex.Unlock()
		release()
		return nil, false
	}
	budget.requests++
	if login {
		budget.logins++
	}
	budget.active++
	this.active++
	this.mutex.Unlock()
	return func() { this.mutex.Lock(); budget.active--; this.active--; this.mutex.Unlock(); release() }, true
}

func (this *webService) Close() error {
	this.closeOnce.Do(func() {
		this.stop()
		this.mutex.Lock()
		access := make([]*webAccess, 0, len(this.access))
		for _, value := range this.access {
			access = append(access, value)
		}
		this.access = make(map[[32]byte]*webAccess)
		this.mutex.Unlock()
		for _, value := range access {
			this.closeErr = goerrors.Join(this.closeErr, value.close())
		}
		this.operations.waitUntilDrained()
		this.loginWorkers.waitUntilDrained()
		this.mutex.Lock()
		for _, attempt := range this.attempts {
			attempt.stop()
		}
		this.attempts = make(map[[32]byte]*webLoginAttempt)
		this.remember = make(map[[32]byte]*webRememberAttempt)
		this.mutex.Unlock()
	})
	return this.closeErr
}

func (this *webService) stop() { this.operations.stop(); this.loginWorkers.stop(); this.cancel() }

func (this *webService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// https.Boundary must already have validated TLS, authority and Origin. This
	// handler is installed only behind that boundary, never exposed standalone.
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		webError(w, http.StatusBadRequest, "query parameters are not accepted")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/_bifroest/") {
		this.describe(w, r)
		return
	}
	if r.URL.Path == webAPI+"terminal" {
		this.serveWebSocketTerminal(w, r)
		return
	}
	switch r.URL.Path {
	case webAPI + "login/password", webAPI + "login/interactive", webAPI + "login/public-key", webAPI + "login/poll", webAPI + "login/reply", webAPI + "login/cancel", webAPI + "access", webAPI + "logout":
	case webAPI + "remember/enroll", webAPI + "remember/resume", webAPI + "remember/revoke", webAPI + "remember/prove":
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		webError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	peer, err := webPeer(r)
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid direct peer")
		return
	}
	isLogin := r.URL.Path == webAPI+"login/password" || r.URL.Path == webAPI+"login/interactive" || r.URL.Path == webAPI+"login/public-key"
	isLogin = isLogin || strings.HasPrefix(r.URL.Path, webAPI+"remember/") && r.URL.Path != webAPI+"remember/prove"
	release, ok := this.admit(peer, isLogin)
	if !ok {
		w.Header().Set("Retry-After", "60")
		webError(w, http.StatusTooManyRequests, "web request limit reached")
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(this.ctx, cancel)
	defer stop()
	// Cancellation must also interrupt a slow request body, not only authorizer
	// calls. Real HTTP/1 and HTTP/2 writers support request read deadlines.
	controller := http.NewResponseController(w)
	readBudget := 20 * time.Second
	if conf := this.service.Configuration.Http; conf != nil && conf.ReadHeaderTimeout.Native() > 0 {
		readBudget = min(readBudget, conf.ReadHeaderTimeout.Native())
	}
	_ = controller.SetReadDeadline(time.Now().Add(readBudget))
	_ = controller.SetWriteDeadline(time.Now().Add(20 * time.Second))
	body := r.Body
	readStopped := make(chan struct{})
	stopRead := context.AfterFunc(ctx, func() {
		defer close(readStopped)
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
		_ = body.Close()
	})
	defer func() {
		if !stopRead() {
			<-readStopped
		}
	}()
	r = r.WithContext(ctx)
	values, err := webJSON(w, r, webRequestFields(r.URL.Path)...)
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}
	scope, err := requestWebScope(r, values["slug"])
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid flow slug")
		return
	}
	if r.URL.Path == webAPI+"login/password" {
		this.password(w, r, scope, values)
		return
	}
	if strings.HasPrefix(r.URL.Path, webAPI+"login/") {
		this.handleAttempt(w, r, scope, peer, values)
		return
	}
	if strings.HasPrefix(r.URL.Path, webAPI+"remember/") {
		this.handleRemember(w, r, scope, peer, values)
		return
	}
	if len(values) != 1 {
		webError(w, http.StatusBadRequest, "only slug is accepted")
		return
	}
	token := webBearer(r)
	if r.URL.Path == webAPI+"logout" {
		if err := this.logout(scope, token); err != nil {
			if goerrors.Is(err, errWebAccessDenied) {
				webError(w, http.StatusUnauthorized, "web access denied")
			} else {
				webError(w, http.StatusServiceUnavailable, "web logout could not be persisted")
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	access, err := this.lookup(scope, token, false)
	if err != nil {
		webError(w, http.StatusUnauthorized, "web access denied")
		return
	}
	conn, err := newWebLoginConnection(ctx, r, scope, access.user)
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid request")
		return
	}
	defer conn.Close()
	base := &environmentContext{service: this.service, connection: conn, authorization: access.auth}
	if err := this.validate(base, access); err != nil {
		webError(w, http.StatusUnauthorized, "web access denied")
		return
	}
	access.mutex.Lock()
	closed := access.closed
	access.mutex.Unlock()
	if closed {
		webError(w, http.StatusUnauthorized, "web access denied")
		return
	}
	webJSONResponse(w, http.StatusOK, this.accessResponse(access, ""))
}

func (this *webService) password(w http.ResponseWriter, r *http.Request, scope webScope, values map[string]string) {
	if len(values) != 3 || !validWebLoginUser(values["user"]) || len(values["password"]) > 4096 {
		webError(w, http.StatusBadRequest, "invalid password request")
		return
	}
	conn, err := newWebLoginConnection(r.Context(), r, scope, values["user"])
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid request")
		return
	}
	defer conn.Close()
	request := &passwordAuthorizeRequest{authorizeRequest: authorizeRequest{service: this.service, connection: conn}, password: values["password"]}
	auth, err := this.service.authorizer.AuthorizePassword(request)
	if err != nil {
		webError(w, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	this.completeAuthentication(w, r.Context(), conn, auth, audit.AuthenticationMethodPassword)
}

func validWebLoginUser(user string) bool {
	return len(user) <= 256 && utf8.ValidString(user) && !strings.ContainsFunc(user, unicode.IsControl)
}

// Every verified adapter converges here. An attempt token, certificate CA
// signature or a public-key eligibility decision cannot substitute for proof.
func (this *webService) completeAuthentication(w http.ResponseWriter, ctx context.Context, conn *webLoginConnection, auth authorization.Authorization, method audit.AuthenticationMethod, primaryKey ...ssh.PublicKey) {
	if auth == nil || !auth.IsAuthorized() || auth.FindSession() == nil {
		webError(w, http.StatusUnauthorized, "authentication denied")
		return
	}
	if auth.Flow() != auth.FindSession().Flow() || ctx.Err() != nil || conn.IsClosed() {
		webError(w, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	ctx = context.WithValue(ctx, auditConnectionContextKey{}, conn)
	base := &environmentContext{service: this.service, connection: conn, authorization: auth, executionContext: ctx}
	if err := this.service.validateTerminalAuthorization(base); err != nil || this.service.sessionConnections.isRevoked(auth.FindSession()) {
		if auditErr := this.service.recordAuthenticationCompletedFor(ctx, conn, auth, method, audit.EventOutcomeDenied, audit.EventReasonSessionIncompatible); auditErr != nil {
			webError(w, http.StatusServiceUnavailable, "authentication unavailable")
			return
		}
		webError(w, http.StatusForbidden, "authentication denied")
		return
	}
	// Mint only after the completed-success audit is durable under its policy.
	if err := this.service.recordAuthenticationCompletedFor(ctx, conn, auth, method, audit.EventOutcomeSuccess, ""); err != nil {
		webError(w, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	if conn.IsClosed() {
		webError(w, http.StatusServiceUnavailable, "authentication unavailable")
		return
	}
	credential := authentication.SessionCredential{Kind: authorization.KindOf(auth), Method: string(method)}
	if method == audit.AuthenticationMethodPublicKey && len(primaryKey) == 1 && primaryKey[0] != nil {
		credential.PublicKey = base64.StdEncoding.EncodeToString(primaryKey[0].Marshal())
	}
	if credential.Validate() != nil {
		credential = authentication.SessionCredential{}
	} // Unsupported adapters may log in without enabling RememberMe.
	token, access, err := this.issue(conn.scope, base, credential, nil)
	if err != nil {
		webError(w, http.StatusServiceUnavailable, "web access unavailable")
		return
	}
	this.service.oidcRefresh.register(auth.FindSession())
	webJSONResponse(w, http.StatusOK, this.accessResponse(access, token))
}

func (this *webService) accessResponse(access *webAccess, token string) any {
	kind := "terminal"
	if this.service.isManagementFlow(access.auth.Flow()) {
		kind = "management"
	}
	return struct {
		Status            string    `json:"status"`
		AccessToken       string    `json:"accessToken,omitempty"`
		ExpiresAt         time.Time `json:"expiresAt"`
		Scope             webScope  `json:"scope"`
		Principal         string    `json:"principal"`
		Environment       string    `json:"environment"`
		TerminalAvailable bool      `json:"terminalAvailable"`
	}{"authorized", token, access.expires, access.scope, access.identity.Principal, kind, kind != "management"}
}

var webDiscoveryTemplate = htmltemplate.Must(htmltemplate.New("discovery").Parse(`<!doctype html><html lang="en-US"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Bifröst</title><h1>Bifröst</h1><p>Published access links. Each link still requires authorization.</p><ul>{{range .}}<li><a href="/{{.}}">{{.}}</a></li>{{else}}<li>No access links published on this host.</li>{{end}}</ul><p>The interactive browser interface is not available yet.</p></html>`))

func (this *webService) describe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		webError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	slug, err := bnet.HttpSlugFromURL(r.URL)
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid flow path")
		return
	}
	scope, err := requestWebScope(r, slug)
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid flow path")
		return
	}
	host := scope.selection().Host
	links, err := this.service.Configuration.Flows.HttpDiscovery(host)
	if err != nil {
		webError(w, http.StatusServiceUnavailable, "discovery unavailable")
		return
	}
	if slug == "" && !strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method != http.MethodHead {
			_ = webDiscoveryTemplate.Execute(w, links)
		}
		return
	}
	fixed, hasFixed, err := this.service.Configuration.Flows.ResolveHttpSlug(host, slug)
	if err != nil {
		webError(w, http.StatusServiceUnavailable, "discovery unavailable")
		return
	}
	requestUser, available := false, false
	for _, flow := range this.service.Configuration.Flows {
		if hasFixed && flow.Name != fixed || !flow.Http.IsEnabled() || !flow.Requirement.Http.MatchesHost(host) || !flow.Requirement.Http.MatchesSlug(slug) {
			continue
		}
		available = true
		requestUser = requestUser || flow.Http.RequestUserEnabled()
	}
	if !available && slug != "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	webJSONResponse(w, http.StatusOK, struct {
		Scope             webScope `json:"scope"`
		RequestUser       bool     `json:"requestUser"`
		PublishedSlugs    []string `json:"publishedSlugs,omitempty"`
		Login             string   `json:"passwordLogin"`
		InteractiveLogin  string   `json:"interactiveLogin"`
		PublicKeyLogin    string   `json:"publicKeyLogin"`
		FrontendAvailable bool     `json:"frontendAvailable"`
	}{scope, requestUser, links, webAPI + "login/password", webAPI + "login/interactive", webAPI + "login/public-key", false})
}

// The current protocol has a flat string-only payload. Reject duplicate keys,
// nulls, unknown fields, trailing JSON and private-key/password extras explicitly.
func webJSON(w http.ResponseWriter, r *http.Request, fields ...string) (map[string]string, error) {
	contentType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || len(params) > 1 || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") {
		return nil, fmt.Errorf("JSON required")
	}
	for key := range params {
		if key != "charset" {
			return nil, fmt.Errorf("invalid content type parameter")
		}
	}
	if r.Header.Get("Content-Encoding") != "" {
		return nil, fmt.Errorf("encoded body forbidden")
	}
	body := http.MaxBytesReader(w, r.Body, webLoginBodyLimit)
	defer body.Close()
	decoder := json.NewDecoder(body)
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("object required")
	}
	result := make(map[string]string)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("invalid field")
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate field")
		}
		allowed := name == "slug"
		for _, field := range fields {
			allowed = allowed || name == field
		}
		if !allowed {
			return nil, fmt.Errorf("unknown field")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, err
		}
		if len(raw) == 0 || raw[0] != '"' || !utf8.Valid(raw) {
			return nil, fmt.Errorf("string required")
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		result[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	if _, exists := result["slug"]; !exists {
		return nil, fmt.Errorf("missing slug")
	}
	return result, nil
}

func webRequestFields(path string) []string {
	switch path {
	case webAPI + "login/password":
		return []string{"user", "password"}
	case webAPI + "login/interactive":
		return []string{"user"}
	case webAPI + "login/public-key":
		return []string{"user", "publicKey"}
	case webAPI + "login/reply":
		return []string{"sequence", "answer", "signature"}
	case webAPI + "remember/enroll":
		return []string{"publicKey"}
	case webAPI + "remember/resume", webAPI + "remember/revoke":
		return []string{"flow", "sessionId", "bindingId"}
	case webAPI + "remember/prove":
		return []string{"signature"}
	default:
		return nil
	}
}

func webJSONResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func webError(w http.ResponseWriter, status int, message string) {
	webJSONResponse(w, status, struct {
		Error string `json:"error"`
	}{message})
}
