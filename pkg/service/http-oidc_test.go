package service

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/webui"
)

// A real TLS/JWKS/token provider that deliberately has NO device endpoint.
type oidcCodeProvider struct {
	*oidcAssociationProvider
	mutex        sync.Mutex
	codes        map[string]url.Values
	badNonce     atomic.Bool
	badAudience  atomic.Bool
	badIssuer    atomic.Bool
	badSignature atomic.Bool
	badAzp       atomic.Bool
	noID         atomic.Bool
	noRefresh    atomic.Bool
	badUserInfo  atomic.Bool
	reject       atomic.Bool
	started      chan struct{}
	canceled     chan struct{}
	hold         bool
	releaseCode  chan struct{}
}

func newOidcCodeProvider(t *testing.T) *oidcCodeProvider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &oidcCodeProvider{oidcAssociationProvider: &oidcAssociationProvider{key: key, refreshStarted: make(chan struct{}, 1), releaseRefresh: make(chan struct{})}, codes: make(map[string]url.Values), started: make(chan struct{}, 1), canceled: make(chan struct{}, 1), releaseCode: make(chan struct{})}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serveCode))
	t.Cleanup(func() { p.release(); p.server.Close() })
	return p
}

func (p *oidcCodeProvider) serveCode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks", "userinfo_endpoint": p.server.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}})
	case "/userinfo":
		subject := "verified-subject"
		if p.badUserInfo.Load() {
			subject = "different-subject"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": subject})
	case "/authorize":
		query := r.URL.Query()
		if query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("nonce") == "" || query.Get("client_id") != "client" {
			http.Error(w, "invalid authorization", 400)
			return
		}
		code, _ := oidcRandom()
		p.mutex.Lock()
		p.codes[code] = query
		p.mutex.Unlock()
		redirect, _ := url.Parse(query.Get("redirect_uri"))
		values := url.Values{"code": {code}, "state": {query.Get("state")}, "iss": {p.server.URL}}
		redirect.RawQuery = values.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	case "/token":
		if r.ParseForm() != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			p.oidcAssociationProvider.serve(w, r)
			return
		}
		if p.hold {
			p.started <- struct{}{}
			select {
			case <-r.Context().Done():
				p.canceled <- struct{}{}
				return
			case <-p.releaseCode:
			}
		}
		p.mutex.Lock()
		query := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		p.mutex.Unlock()
		id, secret, basic := r.BasicAuth()
		if query == nil || !basic || id != "client" || secret != "secret" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != query.Get("redirect_uri") || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != query.Get("code_challenge") || p.reject.Load() {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"DO-NOT-LEAK-CODE"}`))
			return
		}
		n := p.logins.Add(1)
		claims := map[string]any{"iss": p.server.URL, "sub": "verified-subject", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": query.Get("nonce")}
		if p.badNonce.Load() {
			claims["nonce"] = "wrong"
		}
		if p.badAudience.Load() {
			claims["aud"] = "other-client"
		}
		if p.badIssuer.Load() {
			claims["iss"] = "https://other.example.org"
		}
		if p.badAzp.Load() {
			claims["aud"], claims["azp"] = []string{"client", "other"}, "other"
		}
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "local-key"})
		raw, _ := json.Marshal(claims)
		enc := base64.RawURLEncoding.EncodeToString
		input := enc(header) + "." + enc(raw)
		digest := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, stdcrypto.SHA256, digest[:])
		if err != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		if p.badSignature.Load() {
			sig[0] ^= 1
		}
		response := map[string]any{"access_token": fmt.Sprintf("code-access-%d", n), "refresh_token": fmt.Sprintf("code-refresh-%d", n), "token_type": "Bearer", "expires_in": 3600, "id_token": input + "." + enc(sig)}
		if p.noID.Load() {
			delete(response, "id_token")
		}
		if p.noRefresh.Load() {
			delete(response, "refresh_token")
		}
		_ = json.NewEncoder(w).Encode(response)
	default:
		p.oidcAssociationProvider.serve(w, r)
	}
}

func oidcCodeFixture(t *testing.T, configure ...func(*configuration.Configuration, *oidcCodeProvider)) (*service, http.Handler, *oidcCodeProvider, *recordingAuditRecorder) {
	t.Helper()
	p := newOidcCodeProvider(t)
	conf := sessionRecordingTestConfiguration(t, t.TempDir())
	code := &configuration.AuthorizationOidcAuthorizationCode{}
	require.NoError(t, code.SetDefaults())
	code.Issuer = template.MustNewUrl(p.server.URL)
	code.ClientId, code.ClientSecret = template.MustNewString("client"), template.MustNewString("secret")
	conf.Flows[0].Authorization.V = code
	conf.Flows[0].Authorization.RememberMe = configuration.RememberMeAllowed
	conf.Flows[0].Http.RequestUser = commonBool(false)
	conf.Flows[0].DiscoverAsSlug = "Work"
	conf.Http = &configuration.Http{}
	require.NoError(t, conf.Http.SetDefaults())
	conf.Http.Enabled, conf.Http.Domains, conf.Http.Tls.Dummy = true, configuration.HttpDomains{"app.example.org"}, true
	for _, change := range configure {
		change(&conf, p)
	}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, p.server.Client())
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepareContext(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	// Protocol tests exercise document GET safety, not the generated SPA. Keep
	// source-only Go jobs independent of a previous frontend build. Actual browser
	// jobs still use their built resources, including customization and CSP.
	if _, _, err := svc.web.assets.LoginDocument(); errors.Is(err, fs.ErrNotExist) {
		public := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(public, "login.html"), []byte(`<!doctype html><html><head></head><body><div id="root"></div></body></html>`), 0600))
		assetsConf := *conf.Http
		assetsConf.AssetsDirectory = public
		assets, err := webui.New(&assetsConf)
		require.NoError(t, err)
		require.NoError(t, svc.web.assets.Close())
		svc.web.assets = assets
	}
	recorder := &recordingAuditRecorder{}
	for _, flow := range conf.Flows {
		svc.flowAuditRecorders[flow.Name] = recorder
	}
	handler, err := https.Boundary(conf.Http.Domains, svc.web)
	require.NoError(t, err)
	return svc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, p.server.Client())))
	}), p, recorder
}

func oidcRequest(handler http.Handler, method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://app.example.org"+path, strings.NewReader(body))
	r.URL.Scheme, r.URL.Host = "", ""
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "app.example.org"}
	r.RemoteAddr = "192.0.2.44:23456" // Deliberately different from the initiator.
	if method == "POST" {
		r.Header.Set("Origin", "https://app.example.org")
		r.Header.Set("Content-Type", "application/json")
	}
	if strings.HasPrefix(path, configuration.OidcCallbackPath) {
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func oidcView(t *testing.T, response *httptest.ResponseRecorder) oidcBrowserView {
	t.Helper()
	require.Equal(t, 200, response.Code, response.Body.String())
	var view oidcBrowserView
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &view))
	return view
}

func oidcAPI(handler http.Handler, action string, fields map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	body, _ := json.Marshal(fields)
	return oidcRequest(handler, "POST", webAPI+"oidc/"+action, string(body), cookies...)
}

func oidcCallbackRequest(handler http.Handler, callback string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	_, query, _ := strings.Cut(callback, "?")
	return oidcAPI(handler, "callback", map[string]string{"query": query}, cookies...)
}

type oidcBrowserFixture struct {
	ticket, callback, id string
	cookie               *http.Cookie
}

func openOidcBrowser(t *testing.T, handler http.Handler, p *oidcCodeProvider, link string) oidcBrowserFixture {
	t.Helper()
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	ticket := strings.TrimPrefix(parsed.Fragment, "start/")
	page := oidcRequest(handler, "GET", parsed.Path, "")
	require.Equal(t, 200, page.Code, page.Body.String())
	require.Empty(t, page.Result().Cookies(), "document GETs must not consume tickets")
	start := oidcAPI(handler, "start", map[string]string{"ticket": ticket})
	require.Equal(t, 200, start.Code, start.Body.String())
	view := oidcView(t, start)
	var cookie *http.Cookie
	for _, candidate := range start.Result().Cookies() {
		if candidate.Name == oidcCookieName(view.ID) {
			require.Nil(t, cookie)
			cookie = candidate
		}
	}
	require.NotNil(t, cookie)
	require.True(t, cookie.Secure && cookie.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	client := *p.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(view.URL)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, 302, response.StatusCode)
	callback, err := url.Parse(response.Header.Get("Location"))
	require.NoError(t, err)
	return oidcBrowserFixture{ticket: ticket, id: view.ID, callback: callback.RequestURI(), cookie: cookie}
}

// Return an explicitly bound initiating browser. Adversarial tests keep the raw
// handler (or create a second browser) rather than inheriting this cookie.
type oidcTestInitiatingBrowser struct {
	server http.Handler
	cookie *http.Cookie
}

func (this *oidcTestInitiatingBrowser) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = r.Clone(r.Context())
	if _, err := r.Cookie(this.cookie.Name); err == http.ErrNoCookie {
		r.AddCookie(this.cookie)
	}
	this.server.ServeHTTP(w, r)
}

func oidcTestInitiator(handler http.Handler, cookie *http.Cookie) http.Handler {
	return &oidcTestInitiatingBrowser{server: handler, cookie: cookie}
}

func startOidcWeb(t *testing.T, handler http.Handler) (string, string, http.Handler) {
	t.Helper()
	response := webAttemptRequest(handler, "oidc", "", map[string]string{"slug": "Work", "user": ""})
	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	var pending webLoginPending
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &pending))
	token := pending.AttemptToken
	require.NotEmpty(t, token)
	cookies := response.Result().Cookies()
	require.Len(t, cookies, 1)
	require.True(t, cookies[0].Secure && cookies[0].HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
	require.Empty(t, cookies[0].Domain)
	require.Equal(t, "/", cookies[0].Path)
	require.NotContains(t, cookies[0].Name, token[5:])
	require.NotContains(t, response.Body.String(), cookies[0].Value)
	handler = oidcTestInitiator(handler, cookies[0])
	step := waitWebLoginStep(t, handler, token, "Work")
	link := strings.TrimPrefix(step.Message, "Open the following URL in your browser to login: ")
	require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, "").Code)
	return token, link, handler
}

func TestOidcCodeWebLoginUsesRealPKCEAndExistingSessionPolicy(t *testing.T) {
	svc, handler, provider, recorder := oidcCodeFixture(t, func(conf *configuration.Configuration, _ *oidcCodeProvider) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode).Ssh.LoginMessage = template.MustNewString("SSH-only text without a browser link")
	})
	login := func() *webAccess {
		token, link, handler := startOidcWeb(t, handler)
		browser := openOidcBrowser(t, handler, provider, link)
		callback := oidcCallbackRequest(handler, browser.callback, browser.cookie)
		require.Equal(t, 200, callback.Code, callback.Body.String())
		require.NotContains(t, callback.Body.String(), "code-access-")
		require.Equal(t, "authorizing", oidcView(t, callback).Status)
		require.Equal(t, 200, oidcCallbackRequest(handler, browser.callback, browser.cookie).Code)
		access := webTestAccess(t, svc, webTestToken(t, finishWebAttempt(t, handler, token, "Work")), "Work")
		require.Equal(t, "accepted", oidcView(t, oidcAPI(handler, "status", map[string]string{"id": browser.id}, browser.cookie)).Status)
		return access
	}
	require.Zero(t, webSessionCount(t, svc))
	first := login()
	require.Equal(t, "verified-subject", first.identity.Subject)
	require.Equal(t, "oidc-authorization-code", authorization.KindOf(first.auth))
	require.NotNil(t, svc.oidcRefresh.authorizers[first.auth.Flow()])
	stored := oidcAssociationStoredToken(t, first.auth.FindSession())
	require.Equal(t, "code-refresh-1", stored["refresh_token"])
	require.NotContains(t, fmt.Sprint(stored), "code_verifier")
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted)
	require.Len(t, events, 1)
	require.Equal(t, "oidc-authorization-code", events[0].AuthorizationKind)
	second := login()
	require.Equal(t, first.auth.FindSession().Id(), second.auth.FindSession().Id())
	require.Equal(t, 1, webSessionCount(t, svc))
}

func serveOidcSSH(t *testing.T, svc *service, p *oidcCodeProvider) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), oauth2.HTTPClient, p.server.Client()))
	done := make(chan error, 1)
	go func() { done <- svc.server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("SSH server did not stop")
		}
		require.True(t, svc.connectionLifecycle.wait(5*time.Second))
	})
	return listener.Addr().String()
}

func TestOidcCodeSSHNeedsExplicitApprovalWithoutHTTPWorkloadAccess(t *testing.T) {
	for _, decision := range []string{"approve", "deny", "wrong-code", "policy-denied", "policy-fallback", "audit-failed", "custom-message", "external-link"} {
		t.Run(decision, func(t *testing.T) { oidcCodeSSHDecision(t, decision) })
	}
}

func oidcCodeSSHDecision(t *testing.T, decision string) {
	svc, handler, p, recorder := oidcCodeFixture(t, func(conf *configuration.Configuration, _ *oidcCodeProvider) {
		if decision == "custom-message" {
			conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode).Ssh.LoginMessage = template.MustNewString(`[Custom] {{.remote.user}}/{{.connection.transport}} code {{printf "%q" .code}}: {{.url}}`)
		}
		for i := range conf.Flows {
			conf.Flows[i].Http.Enabled = commonBool(false)
		}
		if decision == "policy-denied" || decision == "policy-fallback" {
			if decision == "policy-fallback" {
				fallback := conf.Flows[0]
				fallback.Name, fallback.DiscoverAsSlug = "fallback", ""
				settings := *fallback.Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode)
				settings.Ssh.LoginMessage = template.MustNewString("A cosmetic change must not start another SSO login")
				fallback.Authorization.V = &settings
				conf.Flows = append(conf.Flows, fallback)
			}
			target := &configuration.EnvironmentSsh{}
			require.NoError(t, target.SetDefaults())
			target.Address, target.User = template.MustNewString("127.0.0.1:1"), template.MustNewString("alice")
			target.LoginAllowed, target.AcceptAllHostKeys = template.BoolOf(false), true
			conf.Flows[0].Environment.V = target
		}
	})
	if decision == "audit-failed" {
		recorder.setErrorBeforeRecordForName(audit.EventNameAuthenticationCompleted, errors.New("private-audit-failure"))
	}
	accepted := decision == "approve" || decision == "policy-fallback" || decision == "custom-message" || decision == "external-link"
	for _, accept := range []string{"text/html", "application/json", "*/*"} {
		for _, method := range []string{"GET", "HEAD"} {
			root := oidcRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("Accept", accept)
				handler.ServeHTTP(w, r)
			}), method, "/", "")
			require.Equal(t, 404, root.Code, "no HTTP workload means no WebUI root, even with HTTPS authentication pages")
		}
	}
	address := serveOidcSSH(t, svc, p)
	messages := make(chan string, 4)
	type dialResult struct {
		client *ssh.Client
		err    error
	}
	done := make(chan dialResult, 1)
	go func() {
		client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "alice", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
			Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, instruction string, questions []string, _ []bool) ([]string, error) {
				messages <- instruction
				return make([]string, len(questions)), nil
			})}})
		done <- dialResult{client, err}
	}()
	var message string
	select {
	case message = <-messages:
	case result := <-done:
		t.Fatalf("SSH ended before login link: %v", result.err)
	case <-time.After(5 * time.Second):
		t.Fatal("no SSH login link")
	}
	link := regexp.MustCompile(`https://\S+`).FindString(message)
	require.NotContains(t, message, "\n", "the default SSH instruction is one concise line")
	if decision == "custom-message" {
		require.True(t, strings.HasPrefix(message, "[Custom] alice/ssh code "))
	}
	if decision == "external-link" {
		parsed, err := url.Parse(link)
		require.NoError(t, err)
		foreign := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("Origin", "https://mail.example.net")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
			handler.ServeHTTP(w, r)
		})
		page := oidcRequest(foreign, http.MethodGet, parsed.Path, "")
		require.Equal(t, http.StatusOK, page.Code, page.Body.String())
		require.Empty(t, page.Result().Cookies(), "navigation must not start or bind the SSH login")
		ticket := strings.TrimPrefix(parsed.Fragment, "start/")
		require.Equal(t, http.StatusForbidden, oidcAPI(foreign, "start", map[string]string{"ticket": ticket}).Code)
		svc.web.oidcMutex.Lock()
		phase := svc.web.oidcTickets[sha256.Sum256([]byte(ticket))].phase
		svc.web.oidcMutex.Unlock()
		require.Equal(t, "created", phase, "neither navigation nor a foreign API call may consume the ticket")
	}
	browser := openOidcBrowser(t, handler, p, link)
	callback := oidcCallbackRequest(handler, browser.callback, browser.cookie)
	require.Equal(t, 200, callback.Code, callback.Body.String())
	view := oidcView(t, callback)
	require.Equal(t, "approval", view.Status)
	require.Zero(t, webSessionCount(t, svc))
	select {
	case result := <-done:
		if result.client != nil {
			_ = result.client.Close()
		}
		t.Fatalf("SSH completed without approval: %v", result.err)
	default:
	}
	require.Equal(t, "verified-subject", view.Principal)
	comparison := regexp.MustCompile(`code "([3479CDFHJKMNPRTUVWXY]{2})"`).FindStringSubmatch(message)
	require.Len(t, comparison, 2)
	require.Len(t, view.Choices, 3)
	require.Contains(t, view.Choices, comparison[1])
	action := decision
	if decision == "policy-denied" || decision == "policy-fallback" || decision == "audit-failed" || decision == "custom-message" || decision == "external-link" {
		action = "approve"
	}
	code := comparison[1]
	if decision == "wrong-code" {
		action = "approve"
		for _, choice := range view.Choices {
			if choice != code {
				code = choice
				break
			}
		}
	}
	fields := map[string]string{"id": browser.id, "csrf": "wrong"}
	if action == "approve" {
		fields["code"] = code
	}
	require.Equal(t, 409, oidcAPI(handler, action, fields, browser.cookie).Code)
	fields["csrf"] = view.CSRF
	require.Equal(t, 200, oidcAPI(handler, action, fields, browser.cookie).Code)
	select {
	case result := <-done:
		if accepted {
			require.NoError(t, result.err)
			defer result.client.Close()
		} else {
			require.Error(t, result.err)
			require.Nil(t, result.client)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSH did not complete after approval")
	}
	require.Equal(t, 409, oidcAPI(handler, action, fields, browser.cookie).Code)
	final := oidcView(t, oidcAPI(handler, "status", map[string]string{"id": browser.id}, browser.cookie))
	svc.web.mutex.Lock()
	require.Empty(t, svc.web.access)
	require.Empty(t, svc.web.attempts)
	svc.web.mutex.Unlock()
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted)
	if !accepted {
		require.Equal(t, "denied", final.Status)
		require.Empty(t, events)
		if decision != "audit-failed" {
			require.Zero(t, webSessionCount(t, svc))
		}
		return
	}
	require.Equal(t, "accepted", final.Status)
	require.EqualValues(t, 1, p.logins.Load(), "equivalent fallback flows reuse the approved identity")
	require.Len(t, events, 1)
	require.Equal(t, "oidc-authorization-code", events[0].AuthorizationKind)
}

func TestOidcCodeTimeoutAndParallelTransactions(t *testing.T) {
	svc, handler, p, _ := oidcCodeFixture(t)
	token1, link1, handler := startOidcWeb(t, handler)
	token2, link2, handler := startOidcWeb(t, handler)
	first := openOidcBrowser(t, handler, p, link1)
	second := openOidcBrowser(t, handler, p, link2)
	require.NotEqual(t, first.cookie.Name, second.cookie.Name)
	require.Equal(t, 401, oidcCallbackRequest(handler, first.callback, second.cookie).Code)
	require.Equal(t, 200, oidcCallbackRequest(handler, second.callback, first.cookie, second.cookie).Code)
	require.Equal(t, 200, finishWebAttempt(t, handler, token2, "Work").Code)
	require.Equal(t, 200, oidcCallbackRequest(handler, first.callback, first.cookie, second.cookie).Code)
	require.Equal(t, 200, finishWebAttempt(t, handler, token1, "Work").Code)
	require.Equal(t, 1, webSessionCount(t, svc))

	svc2, handler2, p2, _ := oidcCodeFixture(t, func(conf *configuration.Configuration, _ *oidcCodeProvider) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode).LoginTimeout = common.DurationOf(time.Second)
	})
	token, link, handler2 := startOidcWeb(t, handler2)
	browser := openOidcBrowser(t, handler2, p2, link)
	require.Eventually(t, func() bool {
		svc2.web.oidcMutex.Lock()
		defer svc2.web.oidcMutex.Unlock()
		svc2.web.pruneOidcLocked()
		return oidcTerminal(svc2.web.oidcTickets[sha256.Sum256([]byte(browser.ticket))])
	}, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, 401, oidcCallbackRequest(handler2, browser.callback, browser.cookie).Code)
	require.NotEqual(t, 200, finishWebAttempt(t, handler2, token, "Work").Code)
	require.Zero(t, webSessionCount(t, svc2))
}

func TestOidcCodeWithUnmodifiedOpenSSH(t *testing.T) {
	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is not installed")
	}
	svc, handler, p, recorder := oidcCodeFixture(t, func(conf *configuration.Configuration, _ *oidcCodeProvider) {
		conf.Flows[0].Http.Enabled = commonBool(false)
	})
	address := serveOidcSSH(t, svc, p)
	host, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-F", filepath.Join(t.TempDir(), "empty-config"), "-N", "-p", port,
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile="+filepath.Join(t.TempDir(), "known-hosts"),
		"-o", "PreferredAuthentications=keyboard-interactive", "-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no", "alice@"+host)
	// -F must name a real empty file, also on non-Unix test hosts.
	require.NoError(t, os.WriteFile(cmd.Args[2], nil, 0600))
	output := startOidcOpenSSH(t, cmd)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cancel(); _ = output.Close(); <-done })
	instructions := make(chan string, 1)
	go func() {
		instructions <- readOidcSSHInstruction(output)
	}()
	var instruction string
	select {
	case instruction = <-instructions:
	case <-ctx.Done():
		_ = output.Close()
		t.Fatalf("OpenSSH did not display a complete login instruction: %s", <-instructions)
	}
	link := regexp.MustCompile(`https://[^\s]+/login/#start/[A-Za-z0-9_-]{43}`).FindString(instruction)
	require.NotEmpty(t, link, "OpenSSH ended without a complete login instruction: %s", instruction)
	browser := openOidcBrowser(t, handler, p, link)
	callback := oidcCallbackRequest(handler, browser.callback, browser.cookie)
	require.Equal(t, 200, callback.Code, callback.Body.String())
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted))
	view := oidcView(t, callback)
	comparison := regexp.MustCompile(`code "([3479CDFHJKMNPRTUVWXY]{2})"`).FindStringSubmatch(instruction)
	require.Len(t, comparison, 2)
	code := comparison[1]
	require.Contains(t, view.Choices, code)
	require.Equal(t, 200, oidcAPI(handler, "approve", map[string]string{"id": browser.id, "csrf": view.CSRF, "code": code}, browser.cookie).Code)
	require.Eventually(t, func() bool {
		return len(auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted)) == 1
	}, 3*time.Second, 10*time.Millisecond)
	svc.web.mutex.Lock()
	require.Empty(t, svc.web.access)
	svc.web.mutex.Unlock()
}

func startOidcOpenSSH(t *testing.T, cmd *exec.Cmd) io.ReadCloser {
	t.Helper()
	if runtime.GOOS == "windows" {
		output, err := cmd.StderrPipe()
		require.NoError(t, err)
		require.NoError(t, cmd.Start())
		return output
	}
	// Ubuntu's client routes zero-prompt instructions through notify_start:
	// stderr must be a terminal, otherwise it tries an unavailable GUI Askpass.
	// Exercise what an actual terminal user sees, without relying on debug logs.
	output, err := pty.Start(cmd)
	require.NoError(t, err)
	return output
}

// OpenSSH on Unix prints a zero-prompt instruction without appending a newline.
// A line scanner therefore waits until authentication ends: read bounded chunks
// and require the COMPLETE ticket and comparison code instead of a partial URL.
func readOidcSSHInstruction(reader io.Reader) string {
	reader = io.LimitReader(reader, 64<<10)
	link := regexp.MustCompile(`https://[^\s]+/login/#start/[A-Za-z0-9_-]{43}`)
	code := regexp.MustCompile(`code "[3479CDFHJKMNPRTUVWXY]{2}"`)
	var message strings.Builder
	var buffer [4096]byte
	for {
		n, err := reader.Read(buffer[:])
		_, _ = message.Write(buffer[:n])
		text := message.String()
		if link.MatchString(text) && code.MatchString(text) || err != nil {
			return text
		}
	}
}

func TestOidcSSHInstructionDoesNotRequireANewlineOrEOF(t *testing.T) {
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	done := make(chan string, 1)
	go func() { done <- readOidcSSHInstruction(reader) }()
	_, err := io.WriteString(writer, `Login with code "CD" at https://app.example.org/login/#start/`+strings.Repeat("x", 42))
	require.NoError(t, err)
	select {
	case <-done:
		t.Fatal("accepted a truncated ticket")
	default:
	}
	_, err = io.WriteString(writer, "x")
	require.NoError(t, err)
	select {
	case message := <-done:
		require.Contains(t, message, strings.Repeat("x", 43))
	case <-time.After(time.Second):
		t.Fatal("waited for a newline or EOF after the complete instruction")
	}
}

func TestOidcCodeCallbackRequiresOriginalBrowserAndState(t *testing.T) {
	svc, handler, provider, _ := oidcCodeFixture(t)
	token, link, handler := startOidcWeb(t, handler)
	browser := openOidcBrowser(t, handler, provider, link)
	require.Equal(t, 401, oidcCallbackRequest(handler, browser.callback).Code)
	wrong := *browser.cookie
	wrong.Value, _ = oidcRandom()
	require.Equal(t, 401, oidcCallbackRequest(handler, browser.callback, &wrong).Code)
	require.Equal(t, 401, oidcCallbackRequest(handler, browser.callback, browser.cookie, browser.cookie).Code)
	callback, _ := url.Parse(browser.callback)
	values := callback.Query()
	values.Set("iss", "https://wrong.example.org")
	callback.RawQuery = values.Encode()
	require.Equal(t, 401, oidcCallbackRequest(handler, callback.String(), browser.cookie).Code)
	require.Zero(t, provider.logins.Load())
	require.Zero(t, webSessionCount(t, svc))
	// Forged callbacks did not consume the legitimate transaction.
	require.Equal(t, 200, oidcCallbackRequest(handler, browser.callback, browser.cookie).Code)
	require.Equal(t, 200, finishWebAttempt(t, handler, token, "Work").Code)
}

func TestOidcCodeRejectsInvalidIdentityAndProviderError(t *testing.T) {
	for _, test := range []string{"nonce", "audience", "issuer", "grant", "signature", "azp", "missing-id"} {
		t.Run(test, func(t *testing.T) {
			svc, handler, p, recorder := oidcCodeFixture(t)
			switch test {
			case "nonce":
				p.badNonce.Store(true)
			case "audience":
				p.badAudience.Store(true)
			case "issuer":
				p.badIssuer.Store(true)
			case "grant":
				p.reject.Store(true)
			case "signature":
				p.badSignature.Store(true)
			case "azp":
				p.badAzp.Store(true)
			case "missing-id":
				p.noID.Store(true)
			}
			token, link, handler := startOidcWeb(t, handler)
			browser := openOidcBrowser(t, handler, p, link)
			response := oidcCallbackRequest(handler, browser.callback, browser.cookie)
			require.Equal(t, "denied", oidcView(t, response).Status)
			require.NotContains(t, response.Body.String(), "DO-NOT-LEAK-CODE")
			require.NotEqual(t, 200, finishWebAttempt(t, handler, token, "Work").Code)
			require.Zero(t, webSessionCount(t, svc))
			require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted))
		})
	}
}

func TestOidcCodeRememberMeRefreshAndLossShareSessionPolicy(t *testing.T) {
	svc, handler, p, _ := oidcCodeFixture(t)
	p.release()
	token, link, handler := startOidcWeb(t, handler)
	browser := openOidcBrowser(t, handler, p, link)
	require.Equal(t, 200, oidcCallbackRequest(handler, browser.callback, browser.cookie).Code)
	accessToken := webTestToken(t, finishWebAttempt(t, handler, token, "Work"))
	access := webTestAccess(t, svc, accessToken, "Work")
	key, public := rememberTestKey(t)
	binding := rememberTestEnroll(t, handler, accessToken, public, key)
	resumed := webTestAccess(t, svc, rememberTestResume(t, handler, binding, key), "Work")
	require.Equal(t, access.auth.FindSession().Id(), resumed.auth.FindSession().Id())
	require.Equal(t, "oidc-authorization-code", authorization.KindOf(resumed.auth))
	sess := access.auth.FindSession()
	stored := oidcAssociationStoredToken(t, sess)
	stored["expiry"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NoError(t, sess.SetAuthorizationToken(t.Context(), raw))
	authorizer := svc.authorizer.(*authorization.AuthorizerFacade).OidcRefreshAuthorizer(access.auth.Flow())
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, p.server.Client())
	_, lost, err := authorizer.RefreshSession(ctx, sess)
	require.NoError(t, err)
	require.False(t, lost)
	rotated := oidcAssociationStoredToken(t, sess)
	require.Contains(t, rotated["refresh_token"], "rotated-refresh-")
	require.Equal(t, "authorization_code", rotated["grant"])
	// A later primary login keeps the retained grant, rather than clobbering it.
	token2, link2, handler := startOidcWeb(t, handler)
	browser2 := openOidcBrowser(t, handler, p, link2)
	require.Equal(t, 200, oidcCallbackRequest(handler, browser2.callback, browser2.cookie).Code)
	second := webTestAccess(t, svc, webTestToken(t, finishWebAttempt(t, handler, token2, "Work")), "Work")
	require.Equal(t, sess.Id(), second.auth.FindSession().Id())
	require.Equal(t, rotated["refresh_token"], oidcAssociationStoredToken(t, sess)["refresh_token"])
	p.rejectRefresh.Store(true)
	rotated["expiry"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	raw, err = json.Marshal(rotated)
	require.NoError(t, err)
	require.NoError(t, sess.SetAuthorizationToken(t.Context(), raw))
	_, lost, err = authorizer.RefreshSession(ctx, sess)
	require.Error(t, err)
	require.True(t, lost)
}

func TestOidcCodeAlwaysVerifiesIdentityAndDoesNotRelaxRefreshRequirements(t *testing.T) {
	for _, test := range []string{"hidden-id", "missing-refresh", "userinfo-subject"} {
		t.Run(test, func(t *testing.T) {
			svc, handler, p, _ := oidcCodeFixture(t, func(conf *configuration.Configuration, p *oidcCodeProvider) {
				switch test {
				case "hidden-id":
					conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode).RetrieveIdToken = false
					p.badNonce.Store(true)
				case "userinfo-subject":
					settings := conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode)
					settings.RetrieveIdToken, settings.RetrieveUserInfo = false, true
					p.badUserInfo.Store(true)
				default:
					p.noRefresh.Store(true)
				}
			})
			token, link, handler := startOidcWeb(t, handler)
			browser := openOidcBrowser(t, handler, p, link)
			oidcCallbackRequest(handler, browser.callback, browser.cookie)
			require.NotEqual(t, 200, finishWebAttempt(t, handler, token, "Work").Code)
			require.Zero(t, webSessionCount(t, svc))
		})
	}
}

func TestOidcCodeConcurrentCallbacksConsumeOneCode(t *testing.T) {
	svc, handler, p, _ := oidcCodeFixture(t)
	token, link, handler := startOidcWeb(t, handler)
	browser := openOidcBrowser(t, handler, p, link)
	responses := make(chan int, 2)
	for range 2 {
		go func() { responses <- oidcCallbackRequest(handler, browser.callback, browser.cookie).Code }()
	}
	first, second := <-responses, <-responses
	require.ElementsMatch(t, []int{200, 200}, []int{first, second})
	require.EqualValues(t, 1, p.logins.Load())
	require.Equal(t, 200, finishWebAttempt(t, handler, token, "Work").Code)
	require.NotEqual(t, 200, webAttemptRequest(handler, "poll", token, map[string]string{"slug": "Work"}).Code)
	require.Equal(t, 1, webSessionCount(t, svc))
}

func TestOidcCodeSSHDisconnectInvalidatesPendingLogin(t *testing.T) {
	svc, handler, p, _ := oidcCodeFixture(t)
	address := serveOidcSSH(t, svc, p)
	raw, err := net.DialTimeout("tcp", address, 3*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	messages := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		conn, _, _, err := ssh.NewClientConn(raw, address, &ssh.ClientConfig{User: "alice", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, message string, questions []string, _ []bool) ([]string, error) {
			messages <- message
			return make([]string, len(questions)), nil
		})}})
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	var message string
	select {
	case message = <-messages:
	case <-time.After(3 * time.Second):
		t.Fatal("no SSH login link")
	}
	link := regexp.MustCompile(`https://\S+`).FindString(message)
	browser := openOidcBrowser(t, handler, p, link)
	require.NoError(t, raw.Close())
	require.Eventually(t, func() bool {
		svc.web.oidcMutex.Lock()
		defer svc.web.oidcMutex.Unlock()
		svc.web.pruneOidcLocked()
		return oidcTerminal(svc.web.oidcTickets[sha256.Sum256([]byte(browser.ticket))])
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, 401, oidcCallbackRequest(handler, browser.callback, browser.cookie).Code)
	require.Zero(t, webSessionCount(t, svc))
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SSH client did not stop")
	}
}

func TestOidcCodeRejectsWrongPKCEAndMalformedCallbacks(t *testing.T) {
	svc, handler, p, _ := oidcCodeFixture(t)
	token, link, handler := startOidcWeb(t, handler)
	browser := openOidcBrowser(t, handler, p, link)
	for _, suffix := range []string{"&state=duplicate", "&code=duplicate", "&error=denied", "&error_description=not-an-error", "&unknown=true", "&%ZZ=invalid"} {
		require.Equal(t, 400, oidcCallbackRequest(handler, browser.callback+suffix, browser.cookie).Code)
	}
	svc.web.oidcMutex.Lock()
	svc.web.oidcTickets[sha256.Sum256([]byte(browser.ticket))].verifier, _ = oidcRandom()
	svc.web.oidcMutex.Unlock()
	response := oidcCallbackRequest(handler, browser.callback, browser.cookie)
	require.Equal(t, "denied", oidcView(t, response).Status)
	require.NotEqual(t, 200, finishWebAttempt(t, handler, token, "Work").Code)
	require.Zero(t, p.logins.Load())
	require.Zero(t, webSessionCount(t, svc))
}

func TestOidcCodeCancelInterruptsExchange(t *testing.T) {
	for _, action := range []string{"cancel", "shutdown"} {
		t.Run(action, func(t *testing.T) { oidcCodeInterruptExchange(t, action) })
	}
}

func TestOidcCodeScannerResumeAndForeignReplayDoNotConsumeOrCancelTheLogin(t *testing.T) {
	svc, handler, p, _ := oidcCodeFixture(t)
	token, link, handler := startOidcWeb(t, handler)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	ticket := strings.TrimPrefix(parsed.Fragment, "start/")
	for range 3 {
		page := oidcRequest(handler, "GET", parsed.Path, "")
		require.Equal(t, 200, page.Code)
		require.Empty(t, page.Result().Cookies())
	}
	require.Zero(t, p.logins.Load())
	browser := openOidcBrowser(t, handler, p, link)
	fields := map[string]string{"ticket": ticket}
	require.Equal(t, 401, oidcAPI(handler, "start", fields).Code)
	resumed := oidcView(t, oidcAPI(handler, "start", fields, browser.cookie))
	require.Equal(t, browser.id, resumed.ID)
	require.NotEmpty(t, resumed.URL)
	require.Equal(t, browser.id, oidcView(t, oidcAPI(handler, "status", map[string]string{"id": browser.id}, browser.cookie)).ID)
	page := oidcRequest(handler, "GET", browser.callback, "", browser.cookie)
	require.Equal(t, 200, page.Code)
	require.Zero(t, p.logins.Load(), "callback GET is only a document, not a code exchange")
	require.Equal(t, 200, oidcCallbackRequest(handler, browser.callback, browser.cookie).Code)
	require.Equal(t, 401, oidcAPI(handler, "start", fields).Code)
	require.Equal(t, "authorizing", oidcView(t, oidcAPI(handler, "start", fields, browser.cookie)).Status)
	require.Equal(t, 200, finishWebAttempt(t, handler, token, "Work").Code)
	require.Equal(t, "accepted", oidcView(t, oidcCallbackRequest(handler, browser.callback, browser.cookie)).Status)
	require.EqualValues(t, 1, p.logins.Load())
	require.Equal(t, 1, webSessionCount(t, svc))
}

func TestOidcCodeWebBrowserWaitsForOriginalClaimAndRequiredAudit(t *testing.T) {
	svc, handler, p, recorder := oidcCodeFixture(t)
	token, link, handler := startOidcWeb(t, handler)
	browser := openOidcBrowser(t, handler, p, link)
	require.Equal(t, "authorizing", oidcView(t, oidcCallbackRequest(handler, browser.callback, browser.cookie)).Status)
	require.Eventually(t, func() bool {
		svc.web.mutex.Lock()
		defer svc.web.mutex.Unlock()
		for _, attempt := range svc.web.attempts {
			select {
			case <-attempt.done:
				return true
			default:
			}
		}
		return false
	}, time.Second, time.Millisecond)
	require.Equal(t, "authorizing", oidcView(t, oidcAPI(handler, "status", map[string]string{"id": browser.id}, browser.cookie)).Status)
	recorder.setErrorBeforeRecordForName(audit.EventNameAuthenticationCompleted, errors.New("private-required-audit-failure"))
	require.Equal(t, 503, finishWebAttempt(t, handler, token, "Work").Code)
	final := oidcView(t, oidcAPI(handler, "status", map[string]string{"id": browser.id}, browser.cookie))
	require.Equal(t, "denied", final.Status)
	// Required-audit failure also closes the original connection. Its cancellation
	// may reach the browser before the adapter's explicit denial; neither outcome
	// is success and no private recorder diagnostic may be exposed.
	require.Contains(t, []string{"access_denied", "canceled"}, final.Error)
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted))
	svc.web.mutex.Lock()
	require.Empty(t, svc.web.access)
	svc.web.mutex.Unlock()
}

func TestOidcCodeLostCallbackResponseCanResumeWithoutAnotherExchange(t *testing.T) {
	svc, handler, p, _ := oidcCodeFixture(t, func(_ *configuration.Configuration, p *oidcCodeProvider) { p.hold = true })
	token, link, handler := startOidcWeb(t, handler)
	browser := openOidcBrowser(t, handler, p, link)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- oidcCallbackRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r.WithContext(ctx))
		}), browser.callback, browser.cookie)
	}()
	select {
	case <-p.started:
	case <-time.After(3 * time.Second):
		t.Fatal("exchange did not start")
	}
	cancel() // Losing a browser response does not cancel its original login.
	close(p.releaseCode)
	select {
	case response := <-done:
		require.Equal(t, "authorizing", oidcView(t, response).Status)
	case <-time.After(3 * time.Second):
		t.Fatal("exchange did not finish")
	}
	require.Equal(t, "authorizing", oidcView(t, oidcCallbackRequest(handler, browser.callback, browser.cookie)).Status)
	require.Equal(t, 200, finishWebAttempt(t, handler, token, "Work").Code)
	require.Equal(t, "accepted", oidcView(t, oidcCallbackRequest(handler, browser.callback, browser.cookie)).Status)
	require.EqualValues(t, 1, p.logins.Load())
	svc.web.oidcMutex.Lock()
	defer svc.web.oidcMutex.Unlock()
	tx := svc.web.oidcTickets[sha256.Sum256([]byte(browser.ticket))]
	require.Nil(t, tx.result, "completed records do not retain token material")
	require.Empty(t, tx.verifier)
	tx.retainUntil = time.Now().Add(-time.Second)
	svc.web.pruneOidcLocked()
	require.Empty(t, svc.web.oidcTickets)
	require.Empty(t, svc.web.oidcBrowsers)
	require.Empty(t, svc.web.oidcStates)
}

func oidcCodeInterruptExchange(t *testing.T, action string) {
	svc, handler, p, _ := oidcCodeFixture(t, func(_ *configuration.Configuration, p *oidcCodeProvider) { p.hold = true })
	token, link, handler := startOidcWeb(t, handler)
	browser := openOidcBrowser(t, handler, p, link)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- oidcCallbackRequest(handler, browser.callback, browser.cookie) }()
	select {
	case <-p.started:
	case <-time.After(3 * time.Second):
		t.Fatal("exchange did not start")
	}
	if action == "cancel" {
		require.Equal(t, 204, webAttemptRequest(handler, "cancel", token, map[string]string{"slug": "Work"}).Code)
	} else {
		svc.web.stop()
	}
	select {
	case <-p.canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("exchange did not cancel")
	}
	select {
	case response := <-done:
		require.Contains(t, []string{"denied", "expired"}, oidcView(t, response).Status)
	case <-time.After(3 * time.Second):
		t.Fatal("callback did not return")
	}
	require.Zero(t, webSessionCount(t, svc))
}
