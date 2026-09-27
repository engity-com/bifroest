//go:build cgo && (linux || darwin) && !without_pam

package authorization

import (
	"errors"
	"testing"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/connection"
	berrors "github.com/engity-com/bifroest/pkg/errors"
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
				require.Equal(t, pam.Flags(0), tx.acctMgmtFlags)
			} else {
				require.Equal(t, pam.Silent, tx.flags)
				require.Equal(t, pam.Silent, tx.acctMgmtFlags)
			}
			require.Equal(t, []string{"set-item", "authenticate", "acct-mgmt", "get-item", "get-env-list", "end"}, tx.calls)
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
		{"account management", func(tx *pamTestTransaction) { tx.acctMgmtErr = pam.ErrSystem }, []string{"set-item", "authenticate", "acct-mgmt", "end"}},
		{"get item", func(tx *pamTestTransaction) { tx.getItemErr = failure }, []string{"set-item", "authenticate", "acct-mgmt", "get-item", "end"}},
		{"get environment", func(tx *pamTestTransaction) { tx.getEnvListErr = failure }, []string{"set-item", "authenticate", "acct-mgmt", "get-item", "get-env-list", "end"}},
		{"end", func(tx *pamTestTransaction) { tx.endErr = failure }, []string{"set-item", "authenticate", "acct-mgmt", "get-item", "get-env-list", "end"}},
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
			require.True(t, berrors.IsType(err, berrors.System))
			require.Equal(t, test.expectedCalls, tx.calls)
			if test.name == "authenticate" || test.name == "account management" {
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

func TestPamAuthorizeAccountDenials(t *testing.T) {
	for _, denial := range pamTestAccountDenials() {
		t.Run(denial.Error(), func(t *testing.T) {
			tx := &pamTestTransaction{acctMgmtErr: denial}

			username, env, success, err := pamAuthorizeForPamHandlerFunc(pamTestFactory(tx), "sshd", false, func(pam.Style, string) (string, error) {
				return "", nil
			}, "requested-user", "client.example")

			require.NoError(t, err)
			require.False(t, success)
			require.Empty(t, username)
			require.Nil(t, env)
			require.Equal(t, []string{"set-item", "authenticate", "acct-mgmt", "end"}, tx.calls)
		})
	}
}

func TestPamAccountOnly(t *testing.T) {
	tx := &pamTestTransaction{}
	factory := func(service, user string, handler func(pam.Style, string) (string, error)) (pamTransaction, error) {
		require.Equal(t, "sshd", service)
		require.Equal(t, "canonical-user", user)
		tx.handler = handler
		return tx, nil
	}

	success, err := pamAccountForPamHandlerFunc(factory, "sshd", "canonical-user", "203.0.113.9")

	require.NoError(t, err)
	require.True(t, success)
	require.Equal(t, pam.Silent, tx.acctMgmtFlags)
	require.Equal(t, map[pam.Item]string{pam.Rhost: "203.0.113.9"}, tx.items)
	require.Equal(t, []string{"set-item", "acct-mgmt", "end"}, tx.calls)
}

func TestPamAccountOnlyDenialsAndFailures(t *testing.T) {
	for _, denial := range pamTestAccountDenials() {
		t.Run("denial/"+denial.Error(), func(t *testing.T) {
			tx := &pamTestTransaction{acctMgmtErr: denial}
			success, err := pamAccountForPamHandlerFunc(pamTestFactory(tx), "sshd", "canonical-user", "client.example")
			require.NoError(t, err)
			require.False(t, success)
			require.Equal(t, []string{"set-item", "acct-mgmt", "end"}, tx.calls)
		})
	}

	failure := errors.New("injected PAM failure")
	for _, test := range []struct {
		name          string
		configure     func(*pamTestTransaction)
		expectedCalls []string
	}{
		{"set item", func(tx *pamTestTransaction) { tx.setItemErr = failure }, []string{"set-item", "end"}},
		{"account management", func(tx *pamTestTransaction) { tx.acctMgmtErr = pam.ErrSystem }, []string{"set-item", "acct-mgmt", "end"}},
		{"end", func(tx *pamTestTransaction) { tx.endErr = failure }, []string{"set-item", "acct-mgmt", "end"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &pamTestTransaction{}
			test.configure(tx)
			success, err := pamAccountForPamHandlerFunc(pamTestFactory(tx), "sshd", "canonical-user", "client.example")
			require.Error(t, err)
			require.False(t, success)
			require.True(t, berrors.IsType(err, berrors.System))
			require.Equal(t, test.expectedCalls, tx.calls)
		})
	}
}

func TestPamAccountConversation(t *testing.T) {
	for _, style := range []pam.Style{pam.ErrorMsg, pam.TextInfo} {
		response, err := handlePamAccountConversation(style, "message", false, nil)
		require.NoError(t, err)
		require.Empty(t, response)
	}
	for _, style := range []pam.Style{pam.PromptEchoOff, pam.PromptEchoOn} {
		_, err := handlePamAccountConversation(style, "Password: ", false, nil)
		require.ErrorContains(t, err, "unsupported prompt")
	}

	req := &pamTestInteractiveRequest{}
	handler := interactiveRequestToPamHandlerFunc(req, func(string, Request) (bool, error) { return true, nil })
	_, err := handlePamAccountConversation(pam.ErrorMsg, "error", true, handler)
	require.NoError(t, err)
	_, err = handlePamAccountConversation(pam.TextInfo, "info", true, handler)
	require.NoError(t, err)
	require.Equal(t, []string{"error"}, req.errors)
	require.Equal(t, []string{"info"}, req.infos)
}

func TestPamAuthorizeUsesAccountOnlyConversation(t *testing.T) {
	t.Run("password ignores messages", func(t *testing.T) {
		tx := &pamTestTransaction{user: "canonical-user", acctMgmtStyles: []pam.Style{pam.ErrorMsg, pam.TextInfo}}
		baseHandlerCalls := 0
		_, _, success, err := pamAuthorizeForPamHandlerFunc(pamTestFactoryWithHandler(tx), "sshd", false, func(pam.Style, string) (string, error) {
			baseHandlerCalls++
			return "", nil
		}, "requested-user", "client.example")
		require.NoError(t, err)
		require.True(t, success)
		require.Zero(t, baseHandlerCalls)
	})

	t.Run("interactive forwards messages", func(t *testing.T) {
		tx := &pamTestTransaction{user: "canonical-user", acctMgmtStyles: []pam.Style{pam.ErrorMsg, pam.TextInfo}}
		var styles []pam.Style
		_, _, success, err := pamAuthorizeForPamHandlerFunc(pamTestFactoryWithHandler(tx), "sshd", true, func(style pam.Style, _ string) (string, error) {
			styles = append(styles, style)
			return "", nil
		}, "requested-user", "client.example")
		require.NoError(t, err)
		require.True(t, success)
		require.Equal(t, []pam.Style{pam.ErrorMsg, pam.TextInfo}, styles)
	})

	t.Run("prompt fails closed", func(t *testing.T) {
		tx := &pamTestTransaction{acctMgmtStyles: []pam.Style{pam.PromptEchoOff}}
		_, _, success, err := pamAuthorizeForPamHandlerFunc(pamTestFactoryWithHandler(tx), "sshd", false, func(pam.Style, string) (string, error) {
			return "password", nil
		}, "requested-user", "client.example")
		require.ErrorContains(t, err, "unsupported prompt")
		require.False(t, success)
		require.True(t, berrors.IsType(err, berrors.System))
	})
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
	acctMgmtErr     error
	getItemErr      error
	getEnvListErr   error
	endErr          error
	handler         func(pam.Style, string) (string, error)
	calls           []string
	acctMgmtFlags   pam.Flags
	acctMgmtStyles  []pam.Style
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

func (tx *pamTestTransaction) AcctMgmt(flags pam.Flags) error {
	tx.calls = append(tx.calls, "acct-mgmt")
	tx.acctMgmtFlags = flags
	for _, style := range tx.acctMgmtStyles {
		if _, err := tx.handler(style, "account message"); err != nil {
			return err
		}
	}
	return tx.acctMgmtErr
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

func pamTestFactoryWithHandler(tx *pamTestTransaction) pamTransactionFactory {
	return func(_ string, _ string, handler func(pam.Style, string) (string, error)) (pamTransaction, error) {
		tx.handler = handler
		return tx, nil
	}
}

func pamTestAccountDenials() []error {
	return []error{
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
