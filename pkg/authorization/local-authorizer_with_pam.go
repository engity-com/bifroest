//go:build cgo && linux && !without_pam

package authorization

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/msteinert/pam/v2"

	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalAuthorizer) checkPassword(req PasswordRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	if v := this.conf.PamService; v != "" {
		return authorizeWithLinuxPam(linuxPamOptions{Context: req.Context(), Service: v, Username: requestedUsername, RemoteHost: req.Connection().Remote().Host().String(), Authenticate: true}, passwordRequestToPamHandlerFunc(req, validatePassword), startLinuxPam)
	}

	return this.checkPasswordViaRepository(req, requestedUsername, validatePassword)
}

func (this *LocalAuthorizer) checkInteractive(req InteractiveRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	if v := this.conf.PamService; v != "" {
		return authorizeWithLinuxPam(linuxPamOptions{Context: req.Context(), Service: v, Username: requestedUsername, RemoteHost: req.Connection().Remote().Host().String(), Authenticate: true, Interactive: true}, interactiveRequestToPamHandlerFunc(req, validatePassword), startLinuxPam)
	}

	return this.checkInteractiveViaRepository(req, requestedUsername, validatePassword)
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

type linuxPamTransaction interface {
	Authenticate(pam.Flags) error
	AcctMgmt(pam.Flags) error
	SetItem(pam.Item, string) error
	GetItem(pam.Item) (string, error)
	GetEnvList() (map[string]string, error)
	End() error
}

type linuxPamStart func(string, string, func(pam.Style, string) (string, error)) (linuxPamTransaction, error)

func startLinuxPam(service, username string, handler func(pam.Style, string) (string, error)) (linuxPamTransaction, error) {
	return pam.StartFunc(service, username, handler)
}

type linuxPamOptions struct {
	Context                                 context.Context
	Service, Username, RemoteHost           string
	Authenticate, Interactive, DisallowNull bool
}

// Each handle is synchronous, thread-affine and always ended. Cancellation is
// checked between native calls; a blocking PAM module is never abandoned in a
// detached goroutine. Account management cannot request another primary secret.
func authorizeWithLinuxPam(options linuxPamOptions, handler func(pam.Style, string) (string, error), start linuxPamStart) (username string, env sys.EnvVars, success bool, rErr error) {
	fail := func(err error) (string, sys.EnvVars, bool, error) {
		return "", nil, false, err
	}
	if err := options.Context.Err(); err != nil {
		return fail(err)
	}
	if options.Service == "" || strings.ContainsRune(options.Service+options.Username+options.RemoteHost, 0) {
		return fail(fmt.Errorf("invalid PAM transaction input"))
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	accountPhase := !options.Authenticate
	var callbackErr error
	accountMessages, accountBytes := 0, 0
	conversation := func(style pam.Style, message string) (string, error) {
		if callbackErr != nil {
			return "", callbackErr
		}
		deny := func(err error) (string, error) {
			callbackErr = err
			return "", err
		}
		if err := options.Context.Err(); err != nil {
			return deny(err)
		}
		if !accountPhase {
			return handler(style, message)
		}
		accountMessages++
		accountBytes += len(message)
		if accountMessages > 32 || len(message) > 8<<10 || accountBytes > 32<<10 {
			return deny(fmt.Errorf("PAM account conversation exceeds its bounds"))
		}
		switch style {
		case pam.TextInfo, pam.ErrorMsg:
			return "", nil // No account-phase messages become prompts or task input.
		default:
			return deny(fmt.Errorf("PAM account management requires an unsupported conversation: %w", ErrSessionResumeDenied))
		}
	}
	t, err := start(options.Service, options.Username, conversation)
	if err != nil {
		return fail(err)
	}
	defer func() {
		rErr = errors.Join(rErr, t.End(), options.Context.Err(), callbackErr)
		if rErr != nil {
			username, env, success = "", nil, false
		}
	}()
	if err := t.SetItem(pam.Rhost, options.RemoteHost); err != nil {
		return fail(err)
	}

	var flags pam.Flags
	if !options.Interactive {
		flags = pam.Silent
	}
	if options.DisallowNull {
		flags |= pam.DisallowNullAuthtok
	}
	check := func(operation func(pam.Flags) error) error {
		if err := options.Context.Err(); err != nil {
			return err
		}
		err := operation(flags)
		return errors.Join(err, options.Context.Err(), callbackErr)
	}
	if options.Authenticate {
		if err := check(t.Authenticate); err != nil {
			if isLinuxPamDenial(err) {
				return "", nil, false, nil
			}
			return fail(err)
		}
	}
	accountPhase = true
	if err := check(t.AcctMgmt); err != nil {
		if isLinuxPamDenial(err) {
			return "", nil, false, nil
		}
		return fail(err)
	}
	username, err = t.GetItem(pam.User)
	if err != nil {
		return fail(err)
	}
	if username == "" {
		return fail(fmt.Errorf("PAM returned an empty account identity"))
	}
	env, err = t.GetEnvList()
	if err != nil {
		return fail(err)
	}
	return username, env, true, nil
}

func isLinuxPamDenial(err error) bool {
	for _, denial := range []pam.Error{pam.ErrPermDenied, pam.ErrAuth, pam.ErrAuthinfoUnavail, pam.ErrAuthtokExpired, pam.ErrUserUnknown, pam.ErrIgnore, pam.ErrCredUnavail, pam.ErrAcctExpired, pam.ErrCredInsufficient, pam.ErrMaxtries, pam.ErrNewAuthtokReqd, pam.ErrCredExpired, pam.ErrTryAgain} {
		if errors.Is(err, denial) {
			return true
		}
	}
	return false
}

func (this *LocalAuthorizer) checkPamPasswordAccount(req SessionResumeRequest, name string, id user.Id, policy user.PasswordAccountPolicy) (*user.User, sys.EnvVars, error) {
	return this.checkLinuxPamPasswordAccount(req, name, id, policy, startLinuxPam)
}

func (this *LocalAuthorizer) checkLinuxPamPasswordAccount(req SessionResumeRequest, name string, id user.Id, policy user.PasswordAccountPolicy, start linuxPamStart) (*user.User, sys.EnvVars, error) {
	if this.conf == nil || !this.conf.PamAccountResumeAllowed || this.conf.PamService == "" {
		return nil, nil, ErrSessionResumeUnavailable
	}
	before, err := user.CheckPasswordAccount(req.Context(), this.userRepository, name, id, policy)
	if err != nil {
		return nil, nil, err
	}
	canonical, env, accepted, err := authorizeWithLinuxPam(linuxPamOptions{Context: req.Context(), Service: this.conf.PamService, Username: name, RemoteHost: req.Connection().Remote().Host().String(), DisallowNull: !policy.AllowEmpty}, nil, start)
	if err != nil {
		return nil, nil, err
	}
	if !accepted || canonical != name {
		return nil, nil, ErrSessionResumeDenied
	}
	after, err := user.CheckPasswordAccount(req.Context(), this.userRepository, name, id, policy)
	if err != nil {
		return nil, nil, err
	}
	if !before.IsEqualTo(after) {
		return nil, nil, ErrSessionResumeDenied
	}
	return after, env, nil
}
