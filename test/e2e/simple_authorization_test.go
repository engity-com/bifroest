//go:build e2e && linux && amd64

package e2e_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestSimpleRememberMe(t *testing.T) {
	f, err := newFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	const (
		username           = "simple-remember-e2e"
		restrictedUsername = "simple-restricted-e2e"
		password           = "simple e2e password"
	)
	signer, err := gossh.ParsePrivateKey(mustRead(f.clientKey))
	if err != nil {
		t.Fatal(err)
	}
	authorization := fmt.Sprintf(`      type: simple
      entries:
        - name: %s
          password: %s
        - name: %s
          password: %s
          authorizedKeys: |
            from="192.0.2.0/24" %s`, yamlString(username), yamlString("plain:"+password),
		yamlString(restrictedUsername), yamlString("plain:"+password), strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey()))))
	if err := startAuthorizationService(f, authorization); err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := gossh.ParsePrivateKey(mustRead(f.wrongKey))
	if err != nil {
		t.Fatal(err)
	}

	passwordPrompts := 0
	client, err := dialAuthorizationSSH(f, username, gossh.PublicKeys(signer), 10*time.Second,
		gossh.PasswordCallback(func() (string, error) {
			passwordPrompts++
			return password, nil
		}))
	if err != nil {
		t.Fatalf("first login with offered key and password failed: %v", err)
	}
	if passwordPrompts != 1 {
		t.Errorf("password prompts on first login: got %d, want 1", passwordPrompts)
	}
	if err := runAuthorizationSession(client); err != nil {
		t.Fatalf("first SSH session failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	remembered, err := dialAuthorizationSSH(f, username, gossh.PublicKeys(signer), 10*time.Second)
	if err != nil {
		t.Fatalf("remembered key login without password failed: %v", err)
	}
	defer remembered.Close()
	if err := runAuthorizationSession(remembered); err != nil {
		t.Fatalf("remembered key SSH session failed: %v", err)
	}

	other, err := dialAuthorizationSSH(f, username, gossh.PublicKeys(wrongSigner), 10*time.Second)
	if other != nil {
		_ = other.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("different key was not rejected: %v", err)
	}

	restricted, err := dialAuthorizationSSH(f, restrictedUsername, gossh.PublicKeys(signer), 10*time.Second, gossh.Password(password))
	if err != nil {
		t.Fatalf("password login after restricted key failed: %v", err)
	}
	if err := runAuthorizationSession(restricted); err != nil {
		t.Fatalf("restricted user's SSH session failed: %v", err)
	}
	if err := restricted.Close(); err != nil {
		t.Fatal(err)
	}
	restricted, err = dialAuthorizationSSH(f, restrictedUsername, gossh.PublicKeys(signer), 10*time.Second)
	if restricted != nil {
		_ = restricted.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("remembered key bypassed configured source restriction: %v", err)
	}
}
