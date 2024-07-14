package authorization

import (
	"errors"
	"github.com/engity-com/yasshd/pkg/user"
	"github.com/msteinert/pam/v2"
)

func (this *LocalAuthorizer) checkPassword(req PasswordRequest, u *user.User, validatePassword func(*user.User, string, Request) (bool, error)) (success bool, rErr error) {
	return pamAuthorizeForPamHandlerFunc(this.conf.PamService, passwordRequestToPamHandlerFunc(req, validatePassword), u)
}

func (this *LocalAuthorizer) checkInteractive(req InteractiveRequest, u *user.User, validatePassword func(*user.User, string, Request) (bool, error)) (success bool, rErr error) {
	return pamAuthorizeForPamHandlerFunc(this.conf.PamService, interactiveRequestToPamHandlerFunc(req, validatePassword), u)
}

func passwordRequestToPamHandlerFunc(req PasswordRequest, validatePassword func(*user.User, string, Request) (bool, error)) func(pam.Style, string) (string, error) {
	return func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return req.RemotePassword(), nil
		case pam.PromptEchoOn:
			return req.RemotePassword(), nil
		case pam.ErrorMsg:
			return "", errors.New("error messages are not supported when just checking password")
		case pam.TextInfo:
			return "", errors.New("info messages are not supported when just checking password")
		default:
			return "", errors.New("unrecognized message style")
		}
	}
}

func interactiveRequestToPamHandlerFunc(req InteractiveRequest, validatePassword func(*user.User, string, Request) (bool, error)) func(pam.Style, string) (string, error) {
	return func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return req.Prompt(msg, false)
		case pam.PromptEchoOn:
			return req.Prompt(msg, true)
		case pam.ErrorMsg:
			return "", req.SendError(msg)
		case pam.TextInfo:
			return "", req.SendInfo(msg)
		default:
			return "", errors.New("unrecognized message style")
		}
	}
}

func pamAuthorizeForPamHandlerFunc(pamService string, handler func(pam.Style, string) (string, error), u *user.User) (success bool, rErr error) {
	t, err := pam.StartFunc(pamService, u.Name, handler)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := t.End(); err != nil && rErr == nil {
			rErr = err
			success = false
		}
	}()

	if err := t.Authenticate(pam.Silent); err != nil {
		switch err {
		case pam.ErrAuthinfoUnavail, pam.ErrAuthtokExpired, pam.ErrUserUnknown, pam.ErrIgnore, pam.ErrCredUnavail, pam.ErrAcctExpired, pam.ErrCredInsufficient:
			return false, nil
		default:
			return false, err
		}
	}

	return true, nil
}
