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
	t, err := factory(pamService, requestedUsername, handler)
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := t.End(); err != nil {
			rErr = errors.Join(rErr, err)
			success = false
		}
	}()

	if err := t.SetItem(pam.Rhost, remoteHost); err != nil {
		return fail(err)
	}

	var flags pam.Flags
	if !interactive {
		flags = pam.Silent
	}

	if err := t.Authenticate(flags); err != nil {
		if isPamAuthenticationDenial(err) {
			return "", nil, false, nil
		}
		return fail(err)
	}

	username, err = t.GetItem(pam.User)
	if err != nil {
		return fail(err)
	}

	es, err := t.GetEnvList()
	if err != nil {
		return fail(err)
	}

	return username, es, true, nil
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
