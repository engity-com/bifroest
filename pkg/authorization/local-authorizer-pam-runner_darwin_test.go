//go:build darwin && !without_pam

package authorization

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeDarwinPamRunner struct {
	conversation func(int32, string) (string, error)
	calls        []string
	flags        int32
	account      func() error
	endErr       error
	user         string
}

func (this *fakeDarwinPamRunner) Authenticate(flags int32) error {
	this.calls = append(this.calls, "authenticate")
	this.flags = flags
	return nil
}
func (this *fakeDarwinPamRunner) AcctMgmt(flags int32) error {
	this.calls = append(this.calls, "account")
	this.flags = flags
	if this.account != nil {
		return this.account()
	}
	return nil
}
func (this *fakeDarwinPamRunner) SetItem(item int32, value string) error {
	this.calls = append(this.calls, "rhost:"+value)
	return nil
}
func (this *fakeDarwinPamRunner) GetItem(int32) (string, error) {
	this.calls = append(this.calls, "user")
	return this.user, nil
}
func (this *fakeDarwinPamRunner) GetEnvList() (map[string]string, error) {
	this.calls = append(this.calls, "environment")
	return map[string]string{"FRESH": "native"}, nil
}
func (this *fakeDarwinPamRunner) End() error {
	this.calls = append(this.calls, "end")
	return this.endErr
}
func (this *fakeDarwinPamRunner) start(_, _ string, conversation func(int32, string) (string, error)) (darwinPamTransactionLike, error) {
	this.conversation = conversation
	return this, nil
}

func TestDarwinPamRunnerAccountOnlyDoesNotAuthenticate(t *testing.T) {
	transaction := &fakeDarwinPamRunner{user: "alice"}
	name, env, accepted, err := authorizeWithDarwinPam(darwinPamOptions{Context: t.Context(), Service: "owned", Username: "alice", RemoteHost: "192.0.2.9", DisallowNull: true}, nil, transaction.start)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Equal(t, "alice", name)
	require.Equal(t, "native", env["FRESH"])
	require.Equal(t, darwinPamSilent|darwinPamDisallowNullAuthtok, transaction.flags)
	require.Equal(t, []string{"rhost:192.0.2.9", "account", "user", "environment", "end"}, transaction.calls)
}

func TestDarwinPamRunnerRejectsInvalidOrCanceledInputBeforeNativeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, options := range []darwinPamOptions{
		{Context: t.Context(), Service: "owned", Username: "alice\x00other"},
		{Context: t.Context(), Service: "owned", Username: ""},
		{Context: ctx, Service: "owned", Username: "alice"},
	} {
		_, _, accepted, err := authorizeWithDarwinPam(options, nil, func(string, string, func(int32, string) (string, error)) (darwinPamTransactionLike, error) {
			t.Fatal("invalid inputs reached native PAM")
			return nil, nil
		})
		require.Error(t, err)
		require.False(t, accepted)
	}
}

func TestDarwinPamRunnerPrimaryStillRunsAuthenticationAndAccountPhase(t *testing.T) {
	transaction := &fakeDarwinPamRunner{user: "alice"}
	_, _, accepted, err := authorizeWithDarwinPam(darwinPamOptions{Context: t.Context(), Service: "owned", Username: "alice", Authenticate: true}, func(int32, string) (string, error) { return "", nil }, transaction.start)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Equal(t, []string{"rhost:", "authenticate", "account", "user", "environment", "end"}, transaction.calls)
}

func TestDarwinPamRunnerLatchesIgnoredAccountPrompts(t *testing.T) {
	transaction := &fakeDarwinPamRunner{user: "alice"}
	transaction.account = func() error {
		for range 1024 {
			_, err := transaction.conversation(darwinPamPromptEchoOff, "not allowed")
			require.Error(t, err)
		}
		return nil
	}
	name, env, accepted, err := authorizeWithDarwinPam(darwinPamOptions{Context: t.Context(), Service: "owned", Username: "alice"}, nil, transaction.start)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	require.Less(t, len(err.Error()), 512)
	require.Empty(t, name)
	require.Nil(t, env)
	require.False(t, accepted)
	require.Equal(t, []string{"rhost:", "account", "end"}, transaction.calls)
}

func TestDarwinPamRunnerCancellationAndCleanupCannotPublishEnvironment(t *testing.T) {
	for _, mode := range []string{"cancel", "end-error", "empty-user", "account-denied", "oversized-message"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			transaction := &fakeDarwinPamRunner{user: "alice"}
			switch mode {
			case "cancel":
				transaction.account = func() error { cancel(); return nil }
			case "end-error":
				transaction.endErr = errors.New("cleanup failed")
			case "empty-user":
				transaction.user = ""
			case "account-denied":
				transaction.account = func() error { return &darwinPamError{code: darwinPamAppleAcctLocked} }
			case "oversized-message":
				transaction.account = func() error { _, _ = transaction.conversation(darwinPamTextInfo, strings.Repeat("x", 513)); return nil }
			}
			name, env, accepted, err := authorizeWithDarwinPam(darwinPamOptions{Context: ctx, Service: "owned", Username: "alice"}, nil, transaction.start)
			if mode == "account-denied" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Empty(t, name)
			require.Nil(t, env)
			require.False(t, accepted)
			require.Equal(t, "end", transaction.calls[len(transaction.calls)-1])
		})
	}
}

func TestDarwinPamRunnerDoesNotAbandonAnOutstandingNativeCall(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	releaseNative := sync.OnceFunc(func() { close(release) })
	defer releaseNative()
	transaction := &fakeDarwinPamRunner{user: "alice", account: func() error { close(entered); <-release; return nil }}
	go func() {
		_, _, _, err := authorizeWithDarwinPam(darwinPamOptions{Context: ctx, Service: "owned", Username: "alice"}, nil, transaction.start)
		done <- err
	}()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("abandoned a synchronous PAM call")
	default:
	}
	releaseNative()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("native completion did not release the transaction")
	}
	require.Equal(t, []string{"rhost:", "account", "end"}, transaction.calls)
}
