//go:build e2e && linux && amd64

package e2e_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	gossh "golang.org/x/crypto/ssh"
)

func TestHtpasswdAuthorization(t *testing.T) {
	f, err := newFixture(t)
	if err != nil {
		t.Fatal(err)
	}

	const (
		username         = "htpasswd-e2e"
		rememberUsername = "htpasswd-remember-e2e"
		password         = "correct e2e password"
	)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	authorization := fmt.Sprintf("      type: htpasswd\n      entries: |\n        %s:%s\n        %s:%s", username, hash, rememberUsername, hash)
	if err := startAuthorizationService(f, authorization); err != nil {
		t.Fatal(err)
	}

	t.Run("remembered public key", func(t *testing.T) {
		signer, err := gossh.ParsePrivateKey(mustRead(f.clientKey))
		if err != nil {
			t.Fatal(err)
		}
		wrongSigner, err := gossh.ParsePrivateKey(mustRead(f.wrongKey))
		if err != nil {
			t.Fatal(err)
		}

		passwordPrompts := 0
		client, err := dialAuthorizationSSH(f, rememberUsername, gossh.PublicKeys(signer), 10*time.Second,
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

		remembered, err := dialAuthorizationSSH(f, rememberUsername, gossh.PublicKeys(signer), 10*time.Second)
		if err != nil {
			t.Fatalf("remembered key login without password failed: %v", err)
		}
		defer remembered.Close()
		if err := runAuthorizationSession(remembered); err != nil {
			t.Fatalf("remembered key SSH session failed: %v", err)
		}

		other, err := dialAuthorizationSSH(f, rememberUsername, gossh.PublicKeys(wrongSigner), 10*time.Second)
		if other != nil {
			_ = other.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatalf("different key was not rejected: %v", err)
		}
	})

	t.Run("password login succeeds", func(t *testing.T) {
		client, err := dialAuthorizationSSH(f, username, gossh.Password(password), 10*time.Second)
		if err != nil {
			t.Fatalf("password login failed: %v", err)
		}
		defer client.Close()
		if err := runAuthorizationSession(client); err != nil {
			t.Fatalf("authenticated SSH session failed: %v", err)
		}
	})

	t.Run("wrong password is rejected", func(t *testing.T) {
		client, err := dialAuthorizationSSH(f, username, gossh.Password("definitely wrong"), 10*time.Second)
		if client != nil {
			_ = client.Close()
		}
		if err == nil {
			t.Fatal("SSH login unexpectedly accepted the wrong password")
		}
		if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatalf("wrong password did not produce an SSH authentication rejection: %v", err)
		}
	})
}
