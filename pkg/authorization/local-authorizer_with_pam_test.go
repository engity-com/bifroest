//go:build cgo && (linux || darwin) && !without_pam

package authorization

import (
	"errors"
	"testing"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestPamAuthorizeSuccess(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "interactive"}[interactive], func(t *testing.T) {
			tx := &pamTestTransaction{
				user: "canonical-user",
				env:  map[string]string{"PAM_ENV": "value"},
			}
			factory := func(service, user string, handler func(pam.Style, string) (string, error)) (pamTransaction, error) {
				require.Equal(t, "sshd", service)
				require.Equal(t, "requested-user", user)
				require.NotNil(t, handler)
				return tx, nil
			}

			username, env, success, err := pamAuthorizeForPamHandlerFunc(factory, "sshd", interactive, func(pam.Style, string) (string, error) {
				return "", nil
			}, "requested-user", "203.0.113.7")

			require.NoError(t, err)
			require.True(t, success)
			require.Equal(t, "canonical-user", username)
			require.Equal(t, map[string]string{"PAM_ENV": "value"}, map[string]string(env))
			require.Equal(t, map[pam.Item]string{pam.Rhost: "203.0.113.7"}, tx.items)
			if interactive {
				require.Equal(t, pam.Flags(0), tx.flags)
			} else {
				require.Equal(t, pam.Silent, tx.flags)
			}
			require.Equal(t, []string{"set-item", "authenticate", "get-item", "get-env-list", "end"}, tx.calls)
		})
	}
}

func TestPamAuthorizeExpectedDenials(t *testing.T) {
	denials := []error{
		pam.ErrPermDenied,
		pam.ErrAuth,
		pam.ErrCredInsufficient,
		pam.ErrAuthinfoUnavail,
		pam.ErrUserUnknown,
		pam.ErrMaxtries,
		pam.ErrNewAuthtokReqd,
		pam.ErrAcctExpired,
		pam.ErrCredUnavail,
		pam.ErrCredExpired,
		pam.ErrTryAgain,
		pam.ErrIgnore,
		pam.ErrAuthtokExpired,
	}
	for _, denial := range denials {
		t.Run(denial.Error(), func(t *testing.T) {
			tx := &pamTestTransaction{authenticateErr: denial}

			username, env, success, err := pamAuthorizeForPamHandlerFunc(pamTestFactory(tx), "sshd", false, func(pam.Style, string) (string, error) {
				return "", nil
			}, "requested-user", "client.example")

			require.NoError(t, err)
			require.False(t, success)
			require.Empty(t, username)
			require.Nil(t, env)
			require.Equal(t, []string{"set-item", "authenticate", "end"}, tx.calls)
		})
	}
}

func TestPamAuthorizeFailures(t *testing.T) {
	failure := errors.New("injected PAM failure")
	tests := []struct {
		name          string
		configure     func(*pamTestTransaction)
		expectedCalls []string
	}{
		{"set item", func(tx *pamTestTransaction) { tx.setItemErr = failure }, []string{"set-item", "end"}},
		{"authenticate", func(tx *pamTestTransaction) { tx.authenticateErr = pam.ErrSystem }, []string{"set-item", "authenticate", "end"}},
		{"get item", func(tx *pamTestTransaction) { tx.getItemErr = failure }, []string{"set-item", "authenticate", "get-item", "end"}},
		{"get environment", func(tx *pamTestTransaction) { tx.getEnvListErr = failure }, []string{"set-item", "authenticate", "get-item", "get-env-list", "end"}},
		{"end", func(tx *pamTestTransaction) { tx.endErr = failure }, []string{"set-item", "authenticate", "get-item", "get-env-list", "end"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := &pamTestTransaction{user: "canonical-user"}
			test.configure(tx)

			_, _, success, err := pamAuthorizeForPamHandlerFunc(pamTestFactory(tx), "sshd", false, func(pam.Style, string) (string, error) {
				return "", nil
			}, "requested-user", "client.example")

			require.Error(t, err)
			require.False(t, success)
			require.Equal(t, test.expectedCalls, tx.calls)
			if test.name == "authenticate" {
				require.ErrorIs(t, err, pam.ErrSystem)
			} else {
				require.ErrorIs(t, err, failure)
			}
		})
	}
}

func TestPamAuthorizeStartFailure(t *testing.T) {
	failure := errors.New("cannot start PAM")
	factory := func(string, string, func(pam.Style, string) (string, error)) (pamTransaction, error) {
		return nil, failure
	}

	_, _, success, err := pamAuthorizeForPamHandlerFunc(factory, "sshd", false, func(pam.Style, string) (string, error) {
		return "", nil
	}, "requested-user", "client.example")

	require.ErrorIs(t, err, failure)
	require.False(t, success)
}

func TestPasswordPamConversation(t *testing.T) {
	req := &pamTestPasswordRequest{password: "test-password"}
	validated := 0
	handler := passwordRequestToPamHandlerFunc(req, func(password string, request Request) (bool, error) {
		validated++
		require.Equal(t, "test-password", password)
		require.Same(t, req, request)
		return true, nil
	})

	for _, style := range []pam.Style{pam.PromptEchoOff, pam.PromptEchoOn} {
		response, err := handler(style, "Password: ")
		require.NoError(t, err)
		require.Equal(t, "test-password", response)
	}
	for _, style := range []pam.Style{pam.ErrorMsg, pam.TextInfo} {
		_, err := handler(style, "message")
		require.Error(t, err)
	}
	require.Equal(t, 2, validated)
}

func TestInteractivePamConversation(t *testing.T) {
	req := &pamTestInteractiveRequest{}
	handler := interactiveRequestToPamHandlerFunc(req, func(password string, request Request) (bool, error) {
		require.Equal(t, "response", password)
		require.Same(t, req, request)
		return true, nil
	})

	response, err := handler(pam.PromptEchoOff, "hidden")
	require.NoError(t, err)
	require.Equal(t, "response", response)
	response, err = handler(pam.PromptEchoOn, "visible")
	require.NoError(t, err)
	require.Equal(t, "response", response)
	response, err = handler(pam.ErrorMsg, "error message")
	require.NoError(t, err)
	require.Empty(t, response)
	response, err = handler(pam.TextInfo, "information")
	require.NoError(t, err)
	require.Empty(t, response)

	require.Equal(t, []pamTestPrompt{{"hidden", false}, {"visible", true}}, req.prompts)
	require.Equal(t, []string{"error message"}, req.errors)
	require.Equal(t, []string{"information"}, req.infos)
}

type pamTestTransaction struct {
	items           map[pam.Item]string
	flags           pam.Flags
	user            string
	env             map[string]string
	setItemErr      error
	authenticateErr error
	getItemErr      error
	getEnvListErr   error
	endErr          error
	calls           []string
}

func (tx *pamTestTransaction) SetItem(item pam.Item, value string) error {
	tx.calls = append(tx.calls, "set-item")
	if tx.items == nil {
		tx.items = make(map[pam.Item]string)
	}
	tx.items[item] = value
	return tx.setItemErr
}

func (tx *pamTestTransaction) Authenticate(flags pam.Flags) error {
	tx.calls = append(tx.calls, "authenticate")
	tx.flags = flags
	return tx.authenticateErr
}

func (tx *pamTestTransaction) GetItem(item pam.Item) (string, error) {
	tx.calls = append(tx.calls, "get-item")
	if item != pam.User {
		return "", errors.New("unexpected PAM item")
	}
	return tx.user, tx.getItemErr
}

func (tx *pamTestTransaction) GetEnvList() (map[string]string, error) {
	tx.calls = append(tx.calls, "get-env-list")
	return tx.env, tx.getEnvListErr
}

func (tx *pamTestTransaction) End() error {
	tx.calls = append(tx.calls, "end")
	return tx.endErr
}

func pamTestFactory(tx pamTransaction) pamTransactionFactory {
	return func(string, string, func(pam.Style, string) (string, error)) (pamTransaction, error) {
		return tx, nil
	}
}

type pamTestRequest struct{}

func (*pamTestRequest) Sessions() session.Repository         { return nil }
func (*pamTestRequest) Connection() connection.Connection    { return nil }
func (*pamTestRequest) Context() essh.Context                { return nil }
func (*pamTestRequest) Validate(Authorization) (bool, error) { return true, nil }

type pamTestPasswordRequest struct {
	pamTestRequest
	password string
}

func (req *pamTestPasswordRequest) RemotePassword() string { return req.password }

type pamTestPrompt struct {
	message string
	echoOn  bool
}

type pamTestInteractiveRequest struct {
	pamTestRequest
	prompts []pamTestPrompt
	errors  []string
	infos   []string
}

func (req *pamTestInteractiveRequest) Prompt(message string, echoOn bool) (string, error) {
	req.prompts = append(req.prompts, pamTestPrompt{message, echoOn})
	return "response", nil
}

func (req *pamTestInteractiveRequest) SendError(message string) error {
	req.errors = append(req.errors, message)
	return nil
}

func (req *pamTestInteractiveRequest) SendInfo(message string) error {
	req.infos = append(req.infos, message)
	return nil
}
