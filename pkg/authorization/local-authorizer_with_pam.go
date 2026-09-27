//go:build cgo && (linux || darwin) && !without_pam

package authorization

import (
	"errors"

	"github.com/msteinert/pam/v2"

	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type pamTransaction interface {
	SetItem(pam.Item, string) error
	Authenticate(pam.Flags) error
	AcctMgmt(pam.Flags) error
	GetItem(pam.Item) (string, error)
	GetEnvList() (map[string]string, error)
	End() error
}

type pamTransactionFactory func(string, string, func(pam.Style, string) (string, error)) (pamTransaction, error)

func startPamTransaction(service, user string, handler func(pam.Style, string) (string, error)) (pamTransaction, error) {
	return pam.StartFunc(service, user, handler)
}

func (this *LocalAuthorizer) checkPassword(req PasswordRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	if v := this.conf.PamService; v != "" {
		return pamAuthorizeForPamHandlerFunc(startPamTransaction, v, false, passwordRequestToPamHandlerFunc(req, validatePassword), requestedUsername, req.Connection().Remote().Host().String())
	}
	if !localPamRepositoryFallbackAllowed {
		return "", nil, false, berrors.Config.Newf("configuration parameter pamService must not be empty for local password authentication on Darwin")
	}

	return this.checkPasswordViaRepository(req, requestedUsername, validatePassword)
}

func (this *LocalAuthorizer) checkInteractive(req InteractiveRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	if v := this.conf.PamService; v != "" {
		return pamAuthorizeForPamHandlerFunc(startPamTransaction, v, true, interactiveRequestToPamHandlerFunc(req, validatePassword), requestedUsername, req.Connection().Remote().Host().String())
	}
	if !localPamRepositoryFallbackAllowed {
		return "", nil, false, berrors.Config.Newf("configuration parameter pamService must not be empty for local keyboard-interactive authentication on Darwin")
	}

	return this.checkInteractiveViaRepository(req, requestedUsername, validatePassword)
}

func checkLocalAccount(pamService, username, remoteHost string) (bool, error) {
	if pamService == "" {
		if localPamRepositoryFallbackAllowed {
			return true, nil
		}
		return false, berrors.Config.Newf("configuration parameter pamService must not be empty for local account authorization on Darwin")
	}
	return pamAccountForPamHandlerFunc(startPamTransaction, pamService, username, remoteHost)
}

func passwordRequestToPamHandlerFunc(req PasswordRequest, validatePassword func(string, Request) (bool, error)) func(pam.Style, string) (string, error) {
	check := func() (string, error) {
		password := req.RemotePassword()
		ok, err := validatePassword(password, req)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", pam.ErrCredInsufficient
		}
		return password, nil
	}
	return func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff, pam.PromptEchoOn:
			return check()
		case pam.ErrorMsg:
			return "", errors.New("error messages are not supported when just checking password")
		case pam.TextInfo:
			return "", errors.New("info messages are not supported when just checking password")
		default:
			return "", errors.New("unrecognized message style")
		}
	}
}

func interactiveRequestToPamHandlerFunc(req InteractiveRequest, validatePassword func(string, Request) (bool, error)) func(pam.Style, string) (string, error) {
	check := func(password string, err error) (string, error) {
		if err != nil {
			return "", err
		}
		ok, err := validatePassword(password, req)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", pam.ErrCredInsufficient
		}
		return password, nil
	}
	return func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return check(req.Prompt(msg, false))
		case pam.PromptEchoOn:
			return check(req.Prompt(msg, true))
		case pam.ErrorMsg:
			return "", req.SendError(msg)
		case pam.TextInfo:
			return "", req.SendInfo(msg)
		default:
			return "", errors.New("unrecognized message style")
		}
	}
}

func pamAuthorizeForPamHandlerFunc(factory pamTransactionFactory, pamService string, interactive bool, handler func(pam.Style, string) (string, error), requestedUsername, remoteHost string) (username string, env sys.EnvVars, success bool, rErr error) {
	fail := func(err error) (string, sys.EnvVars, bool, error) {
		return "", nil, false, err
	}
	accountPhase := false
	conversation := func(style pam.Style, message string) (string, error) {
		if !accountPhase {
			return handler(style, message)
		}
		return handlePamAccountConversation(style, message, interactive, handler)
	}
	t, err := factory(pamService, requestedUsername, conversation)
	if err != nil {
		return fail(berrors.System.Newf("cannot start PAM transaction: %w", err))
	}
	defer func() {
		if err := t.End(); err != nil {
			rErr = errors.Join(rErr, berrors.System.Newf("cannot end PAM transaction: %w", err))
			success = false
		}
	}()

	if err := t.SetItem(pam.Rhost, remoteHost); err != nil {
		return fail(berrors.System.Newf("cannot set PAM_RHOST: %w", err))
	}

	var flags pam.Flags
	if !interactive {
		flags = pam.Silent
	}

	if err := t.Authenticate(flags); err != nil {
		if isPamAuthenticationDenial(err) {
			return "", nil, false, nil
		}
		return fail(berrors.System.Newf("PAM authentication failed: %w", err))
	}

	accountPhase = true
	if err := t.AcctMgmt(flags); err != nil {
		if isPamAccountDenial(err) {
			return "", nil, false, nil
		}
		return fail(berrors.System.Newf("PAM account management failed: %w", err))
	}

	username, err = t.GetItem(pam.User)
	if err != nil {
		return fail(berrors.System.Newf("cannot get PAM_USER: %w", err))
	}

	es, err := t.GetEnvList()
	if err != nil {
		return fail(berrors.System.Newf("cannot get PAM environment: %w", err))
	}

	return username, es, true, nil
}

func pamAccountForPamHandlerFunc(factory pamTransactionFactory, pamService, username, remoteHost string) (success bool, rErr error) {
	t, err := factory(pamService, username, func(style pam.Style, message string) (string, error) {
		return handlePamAccountConversation(style, message, false, nil)
	})
	if err != nil {
		return false, berrors.System.Newf("cannot start PAM account transaction: %w", err)
	}
	defer func() {
		if err := t.End(); err != nil {
			rErr = errors.Join(rErr, berrors.System.Newf("cannot end PAM account transaction: %w", err))
			success = false
		}
	}()

	if err := t.SetItem(pam.Rhost, remoteHost); err != nil {
		return false, berrors.System.Newf("cannot set PAM_RHOST: %w", err)
	}
	if err := t.AcctMgmt(pam.Silent); err != nil {
		if isPamAccountDenial(err) {
			return false, nil
		}
		return false, berrors.System.Newf("PAM account management failed: %w", err)
	}
	return true, nil
}

func handlePamAccountConversation(style pam.Style, message string, interactive bool, handler func(pam.Style, string) (string, error)) (string, error) {
	switch style {
	case pam.ErrorMsg, pam.TextInfo:
		if interactive {
			return handler(style, message)
		}
		return "", nil
	case pam.PromptEchoOff, pam.PromptEchoOn:
		return "", errors.New("PAM account management requested an unsupported prompt")
	default:
		return "", errors.New("unrecognized message style")
	}
}

func isPamAuthenticationDenial(err error) bool {
	switch err {
	case pam.ErrPermDenied, pam.ErrAuth, pam.ErrCredInsufficient, pam.ErrAuthinfoUnavail,
		pam.ErrUserUnknown, pam.ErrMaxtries, pam.ErrNewAuthtokReqd, pam.ErrAcctExpired,
		pam.ErrCredUnavail, pam.ErrCredExpired, pam.ErrTryAgain, pam.ErrIgnore,
		pam.ErrAuthtokExpired:
		return true
	default:
		return false
	}
}

func isPamAccountDenial(err error) bool {
	switch err {
	case pam.ErrPermDenied, pam.ErrAuth, pam.ErrCredInsufficient, pam.ErrAuthinfoUnavail,
		pam.ErrUserUnknown, pam.ErrMaxtries, pam.ErrNewAuthtokReqd, pam.ErrAcctExpired,
		pam.ErrCredUnavail, pam.ErrCredExpired, pam.ErrTryAgain, pam.ErrIgnore,
		pam.ErrAuthtokExpired:
		return true
	default:
		return false
	}
}
