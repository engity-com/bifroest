//go:build e2e && linux && amd64

package e2e_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

const (
	oidcClientID     = "bifroest-e2e-client"
	oidcClientSecret = "bifroest-e2e-secret"
	oidcAccessToken  = "bifroest-e2e-access-token"
)

type oidcDeviceOutcome int

const (
	oidcDeviceSuccess oidcDeviceOutcome = iota
	oidcDeviceDenied
)

type oidcDevice struct {
	outcome oidcDeviceOutcome
	polls   int
}

type oidcProviderSnapshot struct {
	deviceRequests int
	tokenRequests  int
	pendingReplies int
	deniedReplies  int
	jwksRequests   int
	userinfoCalls  int
}

type oidcTestProvider struct {
	server       *httptest.Server
	privateKey   *rsa.PrivateKey
	keyID        string
	authMethod   string
	mu           sync.Mutex
	nextOutcome  oidcDeviceOutcome
	nextDeviceID int
	devices      map[string]*oidcDevice
	errors       []string
	snapshot     oidcProviderSnapshot
}

func TestOIDCDeviceAuthorization(t *testing.T) {
	t.Run("pending polling succeeds and sends verification information", func(t *testing.T) {
		provider, f := newOIDCAuthorizationFixture(t)
		provider.setNextOutcome(oidcDeviceSuccess)
		before := provider.getSnapshot()
		var instructions []string
		auth := gossh.KeyboardInteractive(func(_, instruction string, questions []string, _ []bool) ([]string, error) {
			instructions = append(instructions, instruction)
			if len(questions) != 0 {
				return nil, fmt.Errorf("unexpected OIDC questions: %q", questions)
			}
			return []string{}, nil
		})
		client, err := dialAuthorizationSSH(f, "oidc-success", auth, 12*time.Second)
		if err != nil {
			t.Fatalf("OIDC device login failed: %v", err)
		}
		defer client.Close()
		if err := runAuthorizationSession(client); err != nil {
			t.Fatalf("authenticated SSH session failed: %v", err)
		}
		if len(instructions) != 1 {
			t.Fatalf("verification instructions: got %d, want 1: %q", len(instructions), instructions)
		}
		if want := provider.server.URL + "/verify?user_code=E2E-0001"; !strings.Contains(instructions[0], want) {
			t.Fatalf("verification instruction %q does not contain %q", instructions[0], want)
		}

		after := provider.getSnapshot()
		if got := after.deviceRequests - before.deviceRequests; got != 1 {
			t.Errorf("device authorization requests: got %d, want 1", got)
		}
		if got := after.tokenRequests - before.tokenRequests; got != 2 {
			t.Errorf("token endpoint requests: got %d, want 2", got)
		}
		if got := after.pendingReplies - before.pendingReplies; got != 1 {
			t.Errorf("authorization_pending replies: got %d, want 1", got)
		}
		if got := after.jwksRequests - before.jwksRequests; got < 1 {
			t.Errorf("JWKS requests: got %d, want at least 1", got)
		}
		if got := after.userinfoCalls - before.userinfoCalls; got != 1 {
			t.Errorf("userinfo requests: got %d, want 1", got)
		}
	})

	t.Run("access denied is rejected", func(t *testing.T) {
		provider, f := newOIDCAuthorizationFixture(t)
		provider.setNextOutcome(oidcDeviceDenied)
		before := provider.getSnapshot()
		var instructions []string
		auth := gossh.KeyboardInteractive(func(_, instruction string, questions []string, _ []bool) ([]string, error) {
			instructions = append(instructions, instruction)
			if len(questions) != 0 {
				return nil, fmt.Errorf("unexpected OIDC questions: %q", questions)
			}
			return []string{}, nil
		})
		client, err := dialAuthorizationSSH(f, "oidc-denied", auth, 8*time.Second)
		if client != nil {
			_ = client.Close()
		}
		if err == nil {
			t.Fatal("OIDC login unexpectedly succeeded after access_denied")
		}
		if exited, processErr := f.bifroestProc.collect(); exited {
			t.Fatalf("Bifroest exited while rejecting access_denied: %v", processErr)
		}
		if len(instructions) != 1 || !strings.Contains(instructions[0], provider.server.URL+"/verify?user_code=E2E-0001") {
			t.Fatalf("verification instructions were not delivered before denial: %q (SSH error: %v)", instructions, err)
		}
		after := provider.getSnapshot()
		if got := after.deviceRequests - before.deviceRequests; got != 1 {
			t.Errorf("device authorization requests: got %d, want 1", got)
		}
		if got := after.tokenRequests - before.tokenRequests; got != 1 {
			t.Errorf("token polls: got %d, want 1", got)
		}
		if got := after.deniedReplies - before.deniedReplies; got != 1 {
			t.Errorf("access_denied replies: got %d, want 1", got)
		}
		if got := after.userinfoCalls - before.userinfoCalls; got != 0 {
			t.Errorf("userinfo requests after denial: got %d, want 0", got)
		}
	})

	t.Run("client secret basic succeeds", func(t *testing.T) {
		provider, f := newOIDCAuthorizationFixtureWithAuthMethod(t, "client_secret_basic")
		provider.setNextOutcome(oidcDeviceSuccess)
		client, err := dialAuthorizationSSH(f, "oidc-basic", gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
			return []string{}, nil
		}), 12*time.Second)
		if err != nil {
			t.Fatalf("OIDC device login with client_secret_basic failed: %v", err)
		}
		defer client.Close()
		if err := runAuthorizationSession(client); err != nil {
			t.Fatalf("authenticated SSH session failed: %v", err)
		}
	})
}

func newOIDCAuthorizationFixture(t *testing.T) (*oidcTestProvider, *fixture) {
	return newOIDCAuthorizationFixtureWithAuthMethod(t, "client_secret_post")
}

func newOIDCAuthorizationFixtureWithAuthMethod(t *testing.T, authMethod string) (*oidcTestProvider, *fixture) {
	t.Helper()
	provider := newOIDCTestProvider(t, authMethod)
	f, err := newFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { provider.assertNoErrors(t) })
	authorization := fmt.Sprintf(`      type: oidcDeviceAuth
      issuer: %s
      clientId: %s
      clientSecret: %s
      scopes:
        - openid
        - profile
        - email
      retrieveIdToken: true
      retrieveUserInfo: true`, yamlString(provider.server.URL), yamlString(oidcClientID), yamlString(oidcClientSecret))
	if err := startAuthorizationService(f, authorization); err != nil {
		t.Fatal(err)
	}
	return provider, f
}

func newOIDCTestProvider(t *testing.T, authMethod string) *oidcTestProvider {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &oidcTestProvider{
		privateKey: privateKey,
		keyID:      "bifroest-e2e-key",
		authMethod: authMethod,
		devices:    make(map[string]*oidcDevice),
	}
	p.server = httptest.NewServer(http.HandlerFunc(p.serveHTTP))
	t.Cleanup(p.server.Close)
	return p
}

func (p *oidcTestProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		p.serveDiscovery(w, r)
	case "/device":
		p.serveDeviceAuthorization(w, r)
	case "/token":
		p.serveToken(w, r)
	case "/jwks":
		p.serveJWKS(w, r)
	case "/userinfo":
		p.serveUserInfo(w, r)
	case "/verify":
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (p *oidcTestProvider) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		p.recordError("discovery method: got %s, want GET", r.Method)
	}
	metadata := map[string]any{
		"issuer":                                p.server.URL,
		"authorization_endpoint":                p.server.URL + "/authorize",
		"device_authorization_endpoint":         p.server.URL + "/device",
		"token_endpoint":                        p.server.URL + "/token",
		"userinfo_endpoint":                     p.server.URL + "/userinfo",
		"jwks_uri":                              p.server.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	if p.authMethod != "" {
		metadata["token_endpoint_auth_methods_supported"] = []string{p.authMethod}
	}
	p.writeJSON(w, http.StatusOK, metadata)
}

func (p *oidcTestProvider) serveDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		p.recordError("device authorization method: got %s, want POST", r.Method)
	}
	if err := r.ParseForm(); err != nil {
		p.recordError("parse device authorization form: %v", err)
		p.writeOAuthError(w, "invalid_request")
		return
	}
	if got := r.Form.Get("client_id"); got != oidcClientID {
		p.recordError("device client_id: got %q, want %q", got, oidcClientID)
	}
	p.verifyClientAuthentication(r, "device")
	if got := r.Form.Get("scope"); got != "openid profile email" {
		p.recordError("device scope: got %q, want %q", got, "openid profile email")
	}

	p.mu.Lock()
	p.snapshot.deviceRequests++
	p.nextDeviceID++
	id := p.nextDeviceID
	deviceCode := fmt.Sprintf("device-%04d", id)
	userCode := fmt.Sprintf("E2E-%04d", id)
	p.devices[deviceCode] = &oidcDevice{outcome: p.nextOutcome}
	p.mu.Unlock()

	p.writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          p.server.URL + "/verify",
		"verification_uri_complete": p.server.URL + "/verify?user_code=" + url.QueryEscape(userCode),
		"expires_in":                30,
		"interval":                  1,
	})
}

func (p *oidcTestProvider) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		p.recordError("token method: got %s, want POST", r.Method)
	}
	if err := r.ParseForm(); err != nil {
		p.recordError("parse token form: %v", err)
		p.writeOAuthError(w, "invalid_request")
		return
	}
	p.verifyClientAuthentication(r, "token")
	if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:device_code" {
		p.recordError("token grant_type: got %q", got)
	}

	p.mu.Lock()
	p.snapshot.tokenRequests++
	device := p.devices[r.Form.Get("device_code")]
	if device == nil {
		p.mu.Unlock()
		p.recordError("token request contains unknown device_code %q", r.Form.Get("device_code"))
		p.writeOAuthError(w, "invalid_grant")
		return
	}
	device.polls++
	poll := device.polls
	outcome := device.outcome
	if outcome == oidcDeviceSuccess && poll == 1 {
		p.snapshot.pendingReplies++
	}
	if outcome == oidcDeviceDenied {
		p.snapshot.deniedReplies++
	}
	p.mu.Unlock()

	if outcome == oidcDeviceDenied {
		p.writeOAuthError(w, "access_denied")
		return
	}
	if poll == 1 {
		p.writeOAuthError(w, "authorization_pending")
		return
	}
	idToken, err := p.signIDToken()
	if err != nil {
		p.recordError("sign ID token: %v", err)
		http.Error(w, "cannot sign token", http.StatusInternalServerError)
		return
	}
	p.writeJSON(w, http.StatusOK, map[string]any{
		"access_token": oidcAccessToken,
		"token_type":   "Bearer",
		"expires_in":   60,
		"id_token":     idToken,
	})
}

func (p *oidcTestProvider) verifyClientAuthentication(r *http.Request, endpoint string) {
	username, password, basic := r.BasicAuth()
	if p.authMethod == "client_secret_basic" || p.authMethod == "" {
		if !basic || username != oidcClientID || password != oidcClientSecret {
			p.recordError("%s client authentication: got basic=%v username=%q password=%q", endpoint, basic, username, password)
		}
		if got := r.Form.Get("client_secret"); got != "" {
			p.recordError("%s request unexpectedly contains client_secret form parameter", endpoint)
		}
	} else {
		if basic {
			p.recordError("%s request unexpectedly uses HTTP Basic client authentication", endpoint)
		}
		if got := r.Form.Get("client_secret"); got != oidcClientSecret {
			p.recordError("%s client_secret: got %q, want %q", endpoint, got, oidcClientSecret)
		}
	}
	if got := r.Form.Get("client_id"); got != oidcClientID {
		p.recordError("%s client_id: got %q, want %q", endpoint, got, oidcClientID)
	}
}

func (p *oidcTestProvider) serveJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		p.recordError("JWKS method: got %s, want GET", r.Method)
	}
	p.mu.Lock()
	p.snapshot.jwksRequests++
	p.mu.Unlock()
	publicKey := p.privateKey.PublicKey
	p.writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": p.keyID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
		}},
	})
}

func (p *oidcTestProvider) serveUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		p.recordError("userinfo method: got %s, want GET", r.Method)
	}
	p.mu.Lock()
	p.snapshot.userinfoCalls++
	p.mu.Unlock()
	if got := r.Header.Get("Authorization"); got != "Bearer "+oidcAccessToken {
		p.recordError("userinfo authorization: got %q", got)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	p.writeJSON(w, http.StatusOK, map[string]any{
		"sub":            "oidc-e2e-subject",
		"name":           "OIDC E2E User",
		"profile":        p.server.URL + "/users/oidc-e2e-subject",
		"email":          "oidc-e2e@example.invalid",
		"email_verified": true,
	})
}

func (p *oidcTestProvider) signIDToken() (string, error) {
	now := time.Now().Unix()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": p.keyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss":            p.server.URL,
		"sub":            "oidc-e2e-subject",
		"aud":            oidcClientID,
		"iat":            now,
		"exp":            now + 60,
		"name":           "OIDC E2E User",
		"email":          "oidc-e2e@example.invalid",
		"email_verified": true,
	})
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (p *oidcTestProvider) setNextOutcome(outcome oidcDeviceOutcome) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextOutcome = outcome
}

func (p *oidcTestProvider) getSnapshot() oidcProviderSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshot
}

func (p *oidcTestProvider) recordError(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errors = append(p.errors, fmt.Sprintf(format, args...))
}

func (p *oidcTestProvider) assertNoErrors(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.errors) != 0 {
		t.Errorf("embedded OIDC provider errors: %s", strings.Join(p.errors, "; "))
	}
}

func (p *oidcTestProvider) writeOAuthError(w http.ResponseWriter, code string) {
	p.writeJSON(w, http.StatusBadRequest, map[string]any{"error": code})
}

func (p *oidcTestProvider) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		p.recordError("write JSON response: %v", err)
	}
}
