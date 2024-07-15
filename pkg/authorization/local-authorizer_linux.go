package authorization

import (
	"errors"
	"github.com/engity-com/yasshd/pkg/sys"
	"github.com/msteinert/pam/v2"
)

func (this *LocalAuthorizer) checkPassword(req PasswordRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	return pamAuthorizeForPamHandlerFunc(this.conf.PamService, false, passwordRequestToPamHandlerFunc(req, validatePassword), requestedUsername)
}

func (this *LocalAuthorizer) checkInteractive(req InteractiveRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	return pamAuthorizeForPamHandlerFunc(this.conf.PamService, true, interactiveRequestToPamHandlerFunc(req, validatePassword), requestedUsername)
}

func passwordRequestToPamHandlerFunc(req PasswordRequest, validatePassword func(string, Request) (bool, error)) func(pam.Style, string) (string, error) {
	check := func() (string, error) {
		password := req.RemotePassword()
		ok, err := validatePassword(req.RemotePassword(), req)
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

func pamAuthorizeForPamHandlerFunc(pamService string, interactive bool, handler func(pam.Style, string) (string, error), requestedUsername string) (username string, env sys.EnvVars, success bool, rErr error) {
	fail := func(err error) (string, sys.EnvVars, bool, error) {
		return "", nil, false, err
	}
	t, err := pam.StartFunc(pamService, requestedUsername, handler)
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := t.End(); err != nil && rErr == nil {
			rErr = err
			success = false
		}
	}()
	defer func() {
		if v, err := t.GetItem(pam.User); err != nil {
			if rErr == nil {
				rErr = err
			}
			success = false
		} else {
			username = v
		}
	}()

	var flags pam.Flags
	if !interactive {
		flags = pam.Silent
	}

	if err := t.Authenticate(flags); err != nil {
		switch err {
		case pam.ErrAuth, pam.ErrAuthinfoUnavail, pam.ErrAuthtokExpired, pam.ErrUserUnknown, pam.ErrIgnore, pam.ErrCredUnavail, pam.ErrAcctExpired, pam.ErrCredInsufficient:
			return "", nil, false, nil
		default:
			return fail(err)
		}
	}

	es, err := t.GetEnvList()
	if err != nil {
		return fail(err)
	}

	return "", es, true, nil
}
