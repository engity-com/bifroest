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
		username = "htpasswd-e2e"
		password = "correct e2e password"
	)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	authorization := fmt.Sprintf("      type: htpasswd\n      entries: |\n        %s:%s", username, hash)
	if err := startAuthorizationService(f, authorization); err != nil {
		t.Fatal(err)
	}

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
