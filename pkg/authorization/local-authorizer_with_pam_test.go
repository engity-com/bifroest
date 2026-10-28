//go:build linux && cgo && !without_pam

package authorization

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

type linuxPamTestTransaction struct {
	conversation          func(pam.Style, string) (string, error)
	steps                 []string
	username              string
	env                   map[string]string
	failure               string
	authenticate, account func(pam.Flags) error
	flags                 pam.Flags
	remoteHost            string
}

func (this *linuxPamTestTransaction) step(name string) error {
	this.steps = append(this.steps, name)
	if this.failure == name {
		return errors.New("fixture " + name)
	}
	return nil
}
func (this *linuxPamTestTransaction) Authenticate(flags pam.Flags) error {
	if err := this.step("auth"); err != nil {
		return err
	}
	if this.authenticate != nil {
		return this.authenticate(flags)
	}
	return nil
}
func (this *linuxPamTestTransaction) AcctMgmt(flags pam.Flags) error {
	this.flags = flags
	if err := this.step("account"); err != nil {
		return err
	}
	if this.account != nil {
		return this.account(flags)
	}
	return nil
}
func (this *linuxPamTestTransaction) SetItem(item pam.Item, value string) error {
	if item != pam.Rhost {
		return errors.New("unexpected PAM item")
	}
	this.remoteHost = value
	return this.step("rhost")
}
func (this *linuxPamTestTransaction) GetItem(item pam.Item) (string, error) {
	if item != pam.User {
		return "", errors.New("unexpected PAM item")
	}
	return this.username, this.step("user")
}
func (this *linuxPamTestTransaction) GetEnvList() (map[string]string, error) {
	return this.env, this.step("env")
}
func (this *linuxPamTestTransaction) End() error { return this.step("end") }
func (this *linuxPamTestTransaction) start(service, username string, handler func(pam.Style, string) (string, error)) (linuxPamTransaction, error) {
	this.conversation = handler
	if service == "" || username == "" {
		return nil, errors.New("missing PAM selector")
	}
	if err := this.step("start"); err != nil {
		return nil, err
	}
	return this, nil
}

func TestLinuxPamPrimaryAuthenticationRequiresAccountPhaseAndCleanup(t *testing.T) {
	for _, failure := range []string{"", "start", "rhost", "auth", "account", "user", "env", "end"} {
		t.Run(failure, func(t *testing.T) {
			transaction := &linuxPamTestTransaction{username: "canonical", env: map[string]string{"FRESH": "yes"}, failure: failure}
			name, env, accepted, err := authorizeWithLinuxPam(linuxPamOptions{Context: t.Context(), Service: "test", Username: "alice", RemoteHost: "192.0.2.1", Authenticate: true}, nil, transaction.start)
			if failure == "" {
				require.NoError(t, err)
				require.True(t, accepted)
				require.Equal(t, "canonical", name)
				require.Equal(t, sys.EnvVars{"FRESH": "yes"}, env)
				require.Equal(t, []string{"start", "rhost", "auth", "account", "user", "env", "end"}, transaction.steps)
				require.Equal(t, "192.0.2.1", transaction.remoteHost)
			} else {
				require.Error(t, err)
				require.False(t, accepted)
				require.Empty(t, name)
				require.Nil(t, env)
				if failure != "start" {
					require.Equal(t, "end", transaction.steps[len(transaction.steps)-1])
				}
			}
		})
	}
}

func TestLinuxPamAccountPhaseCannotPromptOrIgnoreConversationFailure(t *testing.T) {
	for _, mode := range []string{"secret", "echo", "unknown", "message count", "message size", "message total", "cancel", "ignored failures"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			transaction := &linuxPamTestTransaction{username: "alice"}
			transaction.account = func(pam.Flags) error {
				style, text, count := pam.PromptEchoOff, "unsupported", 1
				switch mode {
				case "echo":
					style = pam.PromptEchoOn
				case "unknown":
					style = pam.Style(999)
				case "message count":
					style, count = pam.TextInfo, 33
				case "message size":
					style, text = pam.TextInfo, strings.Repeat("x", (8<<10)+1)
				case "message total":
					style, text, count = pam.TextInfo, strings.Repeat("x", 8<<10), 5
				case "cancel":
					cancel()
				case "ignored failures":
					count = 1024
				}
				var firstError error
				for range count {
					_, err := transaction.conversation(style, text)
					if mode == "ignored failures" {
						if firstError == nil {
							firstError = err
						}
						require.Same(t, firstError, err, "a broken module cannot grow an unbounded callback-error chain")
					}
				}
				return nil // A module ignoring callback failure must still fail closed.
			}
			_, env, accepted, err := authorizeWithLinuxPam(linuxPamOptions{Context: ctx, Service: "test", Username: "alice", RemoteHost: "192.0.2.1"}, func(pam.Style, string) (string, error) {
				t.Fatal("account must not use a primary conversation")
				return "", nil
			}, transaction.start)
			require.Error(t, err)
			require.False(t, accepted)
			require.Nil(t, env)
			require.NotContains(t, transaction.steps, "auth")
			require.Equal(t, "end", transaction.steps[len(transaction.steps)-1])
		})
	}
}

func TestLinuxPamAccountDenialNeverReadsIdentityOrEnvironment(t *testing.T) {
	for _, denied := range []pam.Error{pam.ErrPermDenied, pam.ErrAcctExpired, pam.ErrNewAuthtokReqd, pam.ErrUserUnknown, pam.ErrMaxtries} {
		transaction := &linuxPamTestTransaction{username: "alice", account: func(pam.Flags) error { return denied }}
		_, env, accepted, err := authorizeWithLinuxPam(linuxPamOptions{Context: t.Context(), Service: "test", Username: "alice", RemoteHost: "192.0.2.1", Authenticate: true}, nil, transaction.start)
		require.NoError(t, err)
		require.False(t, accepted)
		require.Nil(t, env)
		require.Equal(t, []string{"start", "rhost", "auth", "account", "end"}, transaction.steps)
	}
}

func TestLinuxPamPrimaryAccountPromptCannotReplayItsPassword(t *testing.T) {
	transaction := &linuxPamTestTransaction{username: "alice"}
	primaryResponses := 0
	transaction.authenticate = func(pam.Flags) error {
		response, err := transaction.conversation(pam.PromptEchoOff, "primary password")
		require.Equal(t, "current-primary-secret", response)
		return err
	}
	transaction.account = func(pam.Flags) error {
		_, _ = transaction.conversation(pam.PromptEchoOff, "another secret")
		return nil
	}
	_, env, accepted, err := authorizeWithLinuxPam(linuxPamOptions{Context: t.Context(), Service: "test", Username: "alice", RemoteHost: "192.0.2.1", Authenticate: true}, func(pam.Style, string) (string, error) {
		primaryResponses++
		return "current-primary-secret", nil
	}, transaction.start)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	require.False(t, accepted)
	require.Nil(t, env)
	require.Equal(t, 1, primaryResponses, "the account phase cannot request a second use of the primary password")
	require.Equal(t, []string{"start", "rhost", "auth", "account", "end"}, transaction.steps)
}

func TestLinuxPamResumeRequiresOptInFreshIdentityAndAccountOnlyEnvironment(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive"} {
		for _, mode := range []string{"valid", "opt-out", "remapped", "locked during PAM", "groups during validation", "environment during validation", "account denial", "cleanup failure"} {
			t.Run(method+"/"+mode, func(t *testing.T) {
				authorizer, request, repo := newLocalRepositoryResumeFixture(t, method)
				authorizer.conf.PamService = "fixture"
				authorizer.conf.PamAccountResumeAllowed = mode != "opt-out"
				var transactions []*linuxPamTestTransaction
				start := func(service, username string, handler func(pam.Style, string) (string, error)) (linuxPamTransaction, error) {
					transaction := &linuxPamTestTransaction{username: "alice", env: map[string]string{"FRESH": "current"}}
					transactions = append(transactions, transaction)
					switch mode {
					case "remapped":
						transaction.username = "other"
					case "locked during PAM":
						transaction.account = func(pam.Flags) error {
							shadow, err := os.ReadFile(repo.ShadowFilename)
							require.NoError(t, err)
							require.NoError(t, os.WriteFile(repo.ShadowFilename, []byte(strings.Replace(string(shadow), "alice:", "alice:!", 1)), 0600))
							return nil
						}
					case "account denial":
						transaction.account = func(pam.Flags) error { return pam.ErrPermDenied }
					case "cleanup failure":
						transaction.failure = "end"
					case "environment during validation":
						if len(transactions) > 1 {
							transaction.env["FRESH"] = "changed"
						}
					}
					return transaction.start(service, username, handler)
				}
				var req SessionResumeRequest = request
				if mode == "groups during validation" {
					req = localPolicyValidationRequest{request, func(Authorization) (bool, error) {
						require.NoError(t, os.WriteFile(repo.GroupFilename, []byte("primary:x:1001:\nnew:x:2002:alice\n"), 0600))
						return true, nil
					}}
				}
				auth, err := authorizer.resumePasswordAccount(req, request.sess, func(name string, id user.Id, policy user.PasswordAccountPolicy) (*user.User, sys.EnvVars, error) {
					return authorizer.checkLinuxPamPasswordAccount(req, name, id, policy, start)
				})
				if mode == "valid" {
					require.NoError(t, err)
					require.Equal(t, sys.EnvVars{"FRESH": "current"}, auth.EnvVars())
					require.Equal(t, request.sess.Id(), auth.FindSession().Id())
					require.Nil(t, AuthorizedKeyPolicyOf(auth))
					require.Len(t, transactions, 2)
					require.Equal(t, pam.Silent|pam.DisallowNullAuthtok, transactions[1].flags)
				} else {
					require.Error(t, err)
					require.Nil(t, auth)
				}
				for _, transaction := range transactions {
					require.NotContains(t, transaction.steps, "auth")
					require.Equal(t, "end", transaction.steps[len(transaction.steps)-1])
				}
				require.Zero(t, request.Request.(*facadeSelectionRequest).prompts)
				require.Equal(t, "wrong", request.Request.(*facadeSelectionRequest).password, "no primary secret is available to the account-only adapter")
				if mode == "opt-out" {
					require.Empty(t, transactions)
					require.ErrorIs(t, err, ErrSessionResumeUnavailable)
				}
			})
		}
	}
}
