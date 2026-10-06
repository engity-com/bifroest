//go:build e2e && linux && amd64

package e2e_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

const (
	oidcClientID     = "bifroest-e2e-client"
	oidcClientSecret = "bifroest-e2e-secret"
	oidcAccessToken  = "bifroest-e2e-access-token"
	oidcRefreshToken = "bifroest-e2e-refresh-token"
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
	deviceRequests   int
	tokenRequests    int
	pendingReplies   int
	deniedReplies    int
	refreshRequests  int
	refreshSuccesses int
	refreshFailures  int
	invalidGrants    int
	refreshInputs    []string
	jwksRequests     int
	jwksFailures     int
	userinfoCalls    int
}

type oidcTestProvider struct {
	server                  *httptest.Server
	privateKey              *rsa.PrivateKey
	refreshedPrivateKey     *rsa.PrivateKey
	keyID                   string
	authMethod              string
	refreshTokens           bool
	rotateRefreshTokens     bool
	refreshUnavailable      bool
	rejectRefreshAfterFirst bool
	accessTokenLifetime     int
	mu                      sync.Mutex
	jwksUnavailable         bool
	nextOutcome             oidcDeviceOutcome
	nextDeviceID            int
	currentRefreshToken     string
	devices                 map[string]*oidcDevice
	errors                  []string
	snapshot                oidcProviderSnapshot
}

type oidcFixtureOptions struct {
	authMethod              string
	refreshTokens           bool
	rotateRefreshTokens     bool
	rotateIDTokenKey        bool
	refreshUnavailable      bool
	legacyPolicy            bool
	rejectRefreshAfterFirst bool
	accessTokenLifetime     int
	maxUnverifiedFor        time.Duration
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

func TestOIDCRememberMe(t *testing.T) {
	provider, f := newOIDCAuthorizationFixture(t)
	signer, err := gossh.ParsePrivateKey(mustRead(f.clientKey))
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := gossh.ParsePrivateKey(mustRead(f.wrongKey))
	if err != nil {
		t.Fatal(err)
	}

	challenges := 0
	client, err := dialAuthorizationSSH(f, "oidc-remember-me", gossh.PublicKeys(signer), 12*time.Second,
		gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			challenges++
			if len(questions) != 0 {
				return nil, fmt.Errorf("unexpected OIDC questions: %q", questions)
			}
			return []string{}, nil
		}))
	if err != nil {
		t.Fatalf("first OIDC login with offered key failed: %v", err)
	}
	if challenges != 1 {
		t.Errorf("OIDC challenges on first login: got %d, want 1", challenges)
	}
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("first SSH session failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	before := provider.getSnapshot()
	if before.deviceRequests != 1 || before.tokenRequests != 2 {
		t.Fatalf("first OIDC login did not complete device authorization: %+v", before)
	}

	remembered, err := dialAuthorizationSSH(f, "oidc-remember-me", gossh.PublicKeys(signer), 10*time.Second)
	if err != nil {
		t.Fatalf("remembered key login without OIDC challenge failed: %v", err)
	}
	defer remembered.Close()
	if err := runAuthorizationSession(remembered); err != nil {
		t.Fatalf("remembered key SSH session failed: %v", err)
	}

	other, err := dialAuthorizationSSH(f, "oidc-remember-me", gossh.PublicKeys(wrongSigner), 10*time.Second)
	if other != nil {
		_ = other.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("different key was not rejected: %v", err)
	}
	after := provider.getSnapshot()
	if after.deviceRequests != before.deviceRequests || after.tokenRequests != before.tokenRequests {
		t.Errorf("remembered key login unexpectedly restarted OIDC device authorization: before %+v, after %+v", before, after)
	}
}

func TestOIDCLostAccessAfterRefresh(t *testing.T) {
	provider, f := newOIDCAuthorizationFixtureWithOptions(t, oidcFixtureOptions{
		authMethod:              "client_secret_post",
		refreshTokens:           true,
		rejectRefreshAfterFirst: true,
		accessTokenLifetime:     6,
	})
	client, err := dialAuthorizationSSH(f, "oidc-lost-access", gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		if len(questions) != 0 {
			return nil, fmt.Errorf("unexpected OIDC questions: %q", questions)
		}
		return []string{}, nil
	}), 15*time.Second)
	if err != nil {
		t.Fatalf("OIDC device login with refresh token failed: %v", err)
	}
	defer client.Close()
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("authenticated SSH session failed: %v", err)
	}
	if err := poll(10*time.Second, func() error {
		if got := provider.getSnapshot().refreshSuccesses; got != 1 {
			return fmt.Errorf("successful refreshes: got %d, want 1", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("SSH session did not survive successful refresh: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Wait() }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatalf("SSH connection remained open after refresh rejection: %+v", provider.getSnapshot())
	}
	if session, err := client.NewSession(); err == nil {
		_ = session.Close()
		t.Fatal("SSH connection accepted a session after lost access")
	}
	got := provider.getSnapshot()
	if got.refreshRequests != 2 || got.refreshSuccesses != 1 || got.invalidGrants != 1 {
		t.Errorf("refresh exchanges: got %+v, want two requests, one success and one invalid_grant", got)
	}
	if got.tokenRequests != 2 {
		t.Errorf("device token polls: got %d, want 2", got.tokenRequests)
	}
	if exited, processErr := f.bifroestProc.collect(); exited {
		t.Fatalf("Bifroest exited while disposing lost-access session: %v", processErr)
	}
}

func TestOIDCRotatedRefreshTokenSurvivesRestart(t *testing.T) {
	provider, f := newOIDCAuthorizationFixtureWithOptions(t, oidcFixtureOptions{
		authMethod:          "client_secret_post",
		refreshTokens:       true,
		rotateRefreshTokens: true,
		accessTokenLifetime: 8,
	})
	client, err := dialAuthorizationSSH(f, "oidc-rotation", gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		if len(questions) != 0 {
			return nil, fmt.Errorf("unexpected OIDC questions: %q", questions)
		}
		return []string{}, nil
	}), 12*time.Second)
	if err != nil {
		t.Fatalf("OIDC device login failed: %v", err)
	}
	defer client.Close()
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("authenticated SSH session failed: %v", err)
	}
	if err := poll(8*time.Second, func() error {
		if got := provider.getSnapshot().refreshSuccesses; got != 1 {
			return fmt.Errorf("successful refreshes before restart: got %d, want 1", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("SSH session did not survive token rotation: %v", err)
	}
	if err := poll(3*time.Second, func() error {
		sessions, err := os.ReadDir(filepath.Join(f.sessionStorage, "authorization-e2e"))
		if err != nil {
			return err
		}
		if len(sessions) != 1 {
			return fmt.Errorf("persisted sessions: got %d, want 1", len(sessions))
		}
		data, err := os.ReadFile(filepath.Join(f.sessionStorage, "authorization-e2e", sessions[0].Name(), "at"))
		if err != nil {
			return err
		}
		var token struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(data, &token); err != nil {
			return err
		}
		if token.RefreshToken != oidcRefreshToken+"-1" {
			return fmt.Errorf("rotated refresh token not yet persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.bifroestProc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop Bifroest before restart: %v", err)
	}
	if err := f.bifroestProc.wait(5 * time.Second); err != nil {
		t.Fatalf("wait for Bifroest shutdown: %v", err)
	}
	configurationPath := filepath.Join(f.tempDir, "authorization.yaml")
	f.bifroestProc, err = f.launchLoggedProcess("bifroest-restarted", []string{"SSL_CERT_FILE=" + filepath.Join(f.tempDir, "oidc-ca.pem")}, f.bifroest,
		"run", "--configuration="+configurationPath, "--log.level=DEBUG")
	if err != nil {
		t.Fatalf("restart Bifroest: %v", err)
	}
	if err := pollProcess(5*time.Second, f.bifroestProc, func() error {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(f.host, f.port), 500*time.Millisecond)
		if err != nil {
			return err
		}
		return conn.Close()
	}); err != nil {
		t.Fatalf("wait for restarted Bifroest: %v", err)
	}
	if err := poll(9*time.Second, func() error {
		if got := provider.getSnapshot().refreshSuccesses; got < 2 {
			return fmt.Errorf("successful refreshes after restart: got %d, want at least 2", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := provider.getSnapshot()
	if got.deviceRequests != 1 || got.tokenRequests != 2 || got.refreshRequests < 2 || got.invalidGrants != 0 {
		t.Errorf("refresh after restart must reuse the existing session: %+v", got)
	}
	if len(got.refreshInputs) < 2 || got.refreshInputs[0] != oidcRefreshToken || got.refreshInputs[1] != oidcRefreshToken+"-1" {
		t.Errorf("refresh token rotation was not persisted across restart: inputs=%q", got.refreshInputs)
	}
}

func TestOIDCPendingVerificationAfterJWKSOutage(t *testing.T) {
	provider, f := newOIDCAuthorizationFixtureWithOptions(t, oidcFixtureOptions{
		authMethod:          "client_secret_post",
		refreshTokens:       true,
		rotateRefreshTokens: true,
		rotateIDTokenKey:    true,
		accessTokenLifetime: 8,
		maxUnverifiedFor:    22 * time.Second,
	})
	signer, err := gossh.ParsePrivateKey(mustRead(f.clientKey))
	if err != nil {
		t.Fatalf("parse SSH client key: %v", err)
	}
	hostKey, _, _, _, err := gossh.ParseAuthorizedKey(mustRead(f.hostKey + ".pub"))
	if err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort(f.host, f.port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	sshConn, channels, requests, err := gossh.NewClientConn(conn, address, &gossh.ClientConfig{User: "oidc-pending-jwks", HostKeyCallback: gossh.FixedHostKey(hostKey), Auth: []gossh.AuthMethod{gossh.PublicKeys(signer), gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		if len(questions) != 0 {
			return nil, fmt.Errorf("unexpected OIDC questions: %q", questions)
		}
		return []string{}, nil
	})}})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("OIDC device login failed: %v", err)
	}
	client := gossh.NewClient(sshConn, channels, requests)
	defer client.Close()
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("authenticated SSH session failed: %v", err)
	}
	if got := provider.getSnapshot(); got.jwksRequests == 0 || got.jwksFailures != 0 {
		t.Fatalf("initial login did not fetch available JWKS: %+v", got)
	}

	provider.mu.Lock()
	provider.jwksUnavailable = true
	provider.mu.Unlock()

	tokenPath := func() (string, error) {
		sessions, err := os.ReadDir(filepath.Join(f.sessionStorage, "authorization-e2e"))
		if err != nil {
			return "", err
		}
		if len(sessions) != 1 {
			return "", fmt.Errorf("persisted sessions: got %d, want 1", len(sessions))
		}
		return filepath.Join(f.sessionStorage, "authorization-e2e", sessions[0].Name(), "at"), nil
	}
	var initial struct {
		IDToken        string    `json:"id_token"`
		LastVerifiedAt time.Time `json:"lastVerifiedAt"`
	}
	path, err := tokenPath()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &initial); err != nil {
		t.Fatal(err)
	}
	if initial.IDToken == "" || initial.LastVerifiedAt.IsZero() {
		t.Fatalf("initial ID token or verification timestamp missing: %s", data)
	}

	if err := poll(9*time.Second, func() error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var token struct {
			IDToken        string    `json:"id_token"`
			RefreshToken   string    `json:"refresh_token"`
			LastVerifiedAt time.Time `json:"lastVerifiedAt"`
			Pending        *struct {
				IDToken      string `json:"id_token"`
				RefreshToken string `json:"refresh_token"`
			} `json:"pendingVerification"`
		}
		if err := json.Unmarshal(data, &token); err != nil {
			return err
		}
		if token.Pending == nil || token.Pending.RefreshToken != oidcRefreshToken+"-1" || token.Pending.IDToken == "" {
			return fmt.Errorf("rotated refresh token and new ID token not pending yet: %s", data)
		}
		if token.IDToken != initial.IDToken || token.RefreshToken != oidcRefreshToken || !token.LastVerifiedAt.Equal(initial.LastVerifiedAt) {
			return fmt.Errorf("unverified claims or credentials replaced trusted token: %s", data)
		}
		parts := strings.Split(token.Pending.IDToken, ".")
		if len(parts) != 3 {
			return fmt.Errorf("pending ID token is not a JWT")
		}
		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return err
		}
		if !strings.Contains(string(header), `"kid":"bifroest-e2e-refreshed-key"`) {
			return fmt.Errorf("pending ID token does not use refreshed kid: %s", header)
		}
		claims, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return err
		}
		if !strings.Contains(string(claims), `"name":"OIDC E2E Refreshed User"`) {
			return fmt.Errorf("pending ID token does not contain changed claims: %s", claims)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := provider.getSnapshot()
	if before.refreshSuccesses != 1 || before.jwksFailures == 0 || before.invalidGrants != 0 {
		t.Fatalf("first refresh did not encounter transient JWKS failure: %+v", before)
	}
	provider.mu.Lock()
	provider.jwksUnavailable = false
	provider.mu.Unlock()

	// A public-key reconnect rechecks pending credentials without waiting for the worker's minute-long retry.
	verified, err := dialAuthorizationSSH(f, "oidc-pending-jwks", gossh.PublicKeys(signer), 5*time.Second)
	if err != nil {
		t.Fatalf("reconnect to verify pending ID token: %v", err)
	}
	defer verified.Close()
	if err := runAuthorizationSession(verified); err != nil {
		t.Fatalf("SSH session after pending verification failed: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var promoted struct {
		RefreshToken   string          `json:"refresh_token"`
		Expiry         time.Time       `json:"expiry"`
		LastVerifiedAt time.Time       `json:"lastVerifiedAt"`
		Pending        json.RawMessage `json:"pendingVerification"`
	}
	if err := json.Unmarshal(data, &promoted); err != nil {
		t.Fatal(err)
	}
	if promoted.RefreshToken != oidcRefreshToken+"-1" || len(promoted.Pending) != 0 || !promoted.LastVerifiedAt.After(initial.LastVerifiedAt) {
		t.Fatalf("pending credentials not promoted after JWKS recovery: %s", data)
	}
	if wait := time.Until(promoted.Expiry.Add(200 * time.Millisecond)); wait > 0 {
		if wait > 10*time.Second {
			t.Fatalf("promoted access token expiry is unexpectedly far away: %s", promoted.Expiry)
		}
		time.Sleep(wait)
	}
	refreshed, err := dialAuthorizationSSH(f, "oidc-pending-jwks", gossh.PublicKeys(signer), 5*time.Second)
	if err != nil {
		t.Fatalf("reconnect to refresh with rotated token: %v", err)
	}
	defer refreshed.Close()
	if err := runAuthorizationSession(refreshed); err != nil {
		t.Fatalf("SSH session after second refresh failed: %v", err)
	}
	got := provider.getSnapshot()
	if got.refreshSuccesses < 2 || len(got.refreshInputs) < 2 || got.refreshInputs[0] != oidcRefreshToken || got.refreshInputs[1] != oidcRefreshToken+"-1" || got.invalidGrants != 0 || got.jwksRequests <= before.jwksRequests {
		t.Errorf("subsequent refresh did not use rotated token after JWKS recovery: %+v", got)
	}
	if err := runAuthorizationSession(refreshed); err != nil {
		t.Fatalf("SSH session did not survive subsequent refresh: %v", err)
	}
}

func TestOIDCLostAccessRejectsLoginWithoutRefreshToken(t *testing.T) {
	provider, f := newOIDCAuthorizationFixtureWithOptions(t, oidcFixtureOptions{
		authMethod: "client_secret_post",
	})
	client, err := dialAuthorizationSSH(f, "oidc-no-refresh", gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		if len(questions) != 0 {
			return nil, fmt.Errorf("unexpected OIDC questions: %q", questions)
		}
		return []string{}, nil
	}), 12*time.Second)
	if client != nil {
		_ = client.Close()
	}
	if err == nil {
		t.Fatal("OIDC login succeeded without a refresh token under lostAccess")
	}
	if got := provider.getSnapshot().refreshRequests; got != 0 {
		t.Errorf("unexpected refresh requests: %d", got)
	}
}

func TestOIDCLostAccessAfterProviderOutage(t *testing.T) {
	provider, f := newOIDCAuthorizationFixtureWithOptions(t, oidcFixtureOptions{
		authMethod:          "client_secret_post",
		refreshTokens:       true,
		refreshUnavailable:  true,
		accessTokenLifetime: 8,
		maxUnverifiedFor:    12 * time.Second,
	})
	client, err := dialAuthorizationSSH(f, "oidc-provider-outage", gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		if len(questions) != 0 {
			return nil, fmt.Errorf("unexpected OIDC questions: %q", questions)
		}
		return []string{}, nil
	}), 15*time.Second)
	if err != nil {
		t.Fatalf("OIDC device login before provider outage failed: %v", err)
	}
	defer client.Close()
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("authenticated SSH session failed: %v", err)
	}
	if err := poll(8*time.Second, func() error {
		if provider.getSnapshot().refreshFailures == 0 {
			return fmt.Errorf("no transient refresh failure observed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("SSH session did not survive a temporary refresh failure: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Wait() }()
	select {
	case <-closed:
	case <-time.After(12 * time.Second):
		t.Fatalf("SSH connection remained open past the verification deadline: %+v", provider.getSnapshot())
	}
	if session, err := client.NewSession(); err == nil {
		_ = session.Close()
		t.Fatal("SSH connection accepted a session after the verification deadline")
	}
	got := provider.getSnapshot()
	if got.refreshFailures == 0 || got.refreshSuccesses != 0 || got.invalidGrants != 0 {
		t.Errorf("refresh exchanges: got %+v, want only transient failures", got)
	}
}

func newOIDCAuthorizationFixture(t *testing.T) (*oidcTestProvider, *fixture) {
	return newOIDCAuthorizationFixtureWithAuthMethod(t, "client_secret_post")
}

func newOIDCAuthorizationFixtureWithAuthMethod(t *testing.T, authMethod string) (*oidcTestProvider, *fixture) {
	return newOIDCAuthorizationFixtureWithOptions(t, oidcFixtureOptions{authMethod: authMethod, legacyPolicy: true})
}

func newOIDCAuthorizationFixtureWithOptions(t *testing.T, opts oidcFixtureOptions) (*oidcTestProvider, *fixture) {
	t.Helper()
	provider := newOIDCTestProvider(t, opts)
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
	if opts.legacyPolicy {
		authorization += `
      forceDisposeSessionOn: never
      refreshToken:
        mode: never`
	} else if opts.refreshTokens {
		authorization += `
      refreshToken:
        atLifetimePercent: 50`
		if opts.maxUnverifiedFor > 0 {
			authorization += fmt.Sprintf("\n        maxUnverifiedFor: %s", opts.maxUnverifiedFor)
		}
	}
	caCertificate := filepath.Join(f.tempDir, "oidc-ca.pem")
	if err := os.WriteFile(caCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := startAuthorizationService(f, authorization, "SSL_CERT_FILE="+caCertificate); err != nil {
		t.Fatal(err)
	}
	return provider, f
}

func newOIDCTestProvider(t *testing.T, opts oidcFixtureOptions) *oidcTestProvider {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var refreshedPrivateKey *rsa.PrivateKey
	if opts.rotateIDTokenKey {
		refreshedPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
	}
	p := &oidcTestProvider{
		privateKey:              privateKey,
		refreshedPrivateKey:     refreshedPrivateKey,
		keyID:                   "bifroest-e2e-key",
		authMethod:              opts.authMethod,
		refreshTokens:           opts.refreshTokens,
		rotateRefreshTokens:     opts.rotateRefreshTokens,
		refreshUnavailable:      opts.refreshUnavailable,
		rejectRefreshAfterFirst: opts.rejectRefreshAfterFirst,
		accessTokenLifetime:     opts.accessTokenLifetime,
		currentRefreshToken:     oidcRefreshToken,
		devices:                 make(map[string]*oidcDevice),
	}
	if p.accessTokenLifetime == 0 {
		p.accessTokenLifetime = 60
	}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serveHTTP))
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
	switch grant := r.Form.Get("grant_type"); grant {
	case "refresh_token":
		p.mu.Lock()
		p.snapshot.refreshRequests++
		input := r.Form.Get("refresh_token")
		p.snapshot.refreshInputs = append(p.snapshot.refreshInputs, input)
		valid := p.refreshTokens && input == p.currentRefreshToken
		reject := p.rejectRefreshAfterFirst && p.snapshot.refreshSuccesses > 0
		if valid && p.refreshUnavailable {
			p.snapshot.refreshFailures++
		} else if valid && !reject {
			p.snapshot.refreshSuccesses++
			if p.rotateRefreshTokens {
				p.currentRefreshToken = fmt.Sprintf("%s-%d", oidcRefreshToken, p.snapshot.refreshSuccesses)
			}
		} else if valid {
			p.snapshot.invalidGrants++
		} else if p.rotateRefreshTokens {
			p.snapshot.invalidGrants++
		}
		p.mu.Unlock()
		if !valid {
			p.recordError("unknown refresh_token %q", r.Form.Get("refresh_token"))
			p.writeOAuthError(w, "invalid_grant")
			return
		}
		if p.refreshUnavailable {
			p.writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "server_error"})
			return
		}
		if reject {
			p.writeOAuthError(w, "invalid_grant")
			return
		}
	case "urn:ietf:params:oauth:grant-type:device_code":
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
	default:
		p.recordError("token grant_type: got %q", grant)
		p.writeOAuthError(w, "unsupported_grant_type")
		return
	}
	idToken, err := p.signIDToken(r.Form.Get("grant_type") == "refresh_token")
	if err != nil {
		p.recordError("sign ID token: %v", err)
		http.Error(w, "cannot sign token", http.StatusInternalServerError)
		return
	}
	response := map[string]any{
		"access_token": oidcAccessToken,
		"token_type":   "Bearer",
		"expires_in":   p.accessTokenLifetime,
		"id_token":     idToken,
	}
	if p.refreshTokens {
		if p.rotateRefreshTokens {
			p.mu.Lock()
			response["refresh_token"] = p.currentRefreshToken
			p.mu.Unlock()
		} else {
			response["refresh_token"] = oidcRefreshToken
		}
	}
	p.writeJSON(w, http.StatusOK, response)
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
	unavailable := p.jwksUnavailable
	if unavailable {
		p.snapshot.jwksFailures++
	}
	refreshed := p.snapshot.refreshSuccesses > 0
	p.mu.Unlock()
	if unavailable {
		p.writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "server_error"})
		return
	}
	publicKey := p.privateKey.PublicKey
	keys := []map[string]any{{
		"kty": "RSA",
		"kid": p.keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
	}}
	if refreshed && p.refreshedPrivateKey != nil {
		keys = append(keys, map[string]any{
			"kty": "RSA", "kid": "bifroest-e2e-refreshed-key", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(p.refreshedPrivateKey.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
		})
	}
	p.writeJSON(w, http.StatusOK, map[string]any{
		"keys": keys,
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

func (p *oidcTestProvider) signIDToken(refresh bool) (string, error) {
	now := time.Now().Unix()
	key, kid, name := p.privateKey, p.keyID, "OIDC E2E User"
	if refresh && p.refreshedPrivateKey != nil {
		key, kid, name = p.refreshedPrivateKey, "bifroest-e2e-refreshed-key", "OIDC E2E Refreshed User"
	}
	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss":            p.server.URL,
		"sub":            "oidc-e2e-subject",
		"aud":            oidcClientID,
		"iat":            now,
		"exp":            now + 60,
		"name":           name,
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
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
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
	snapshot := p.snapshot
	snapshot.refreshInputs = append([]string(nil), snapshot.refreshInputs...)
	return snapshot
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
