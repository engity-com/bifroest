//go:build windows

package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func (this *LocalAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "local", this.flow)
	if err != nil {
		return nil, err
	}
	if key == nil {
		if this.conf == nil {
			return nil, ErrSessionResumeUnavailable
		}
		return this.resumeWindowsPasswordAccount(req, sess, func(ctx context.Context, account windowslocal.Account, policy windowslocal.PasswordAccountPolicy) (windowslocal.PasswordAccountView, error) {
			return windowslocal.CheckPasswordAccount(ctx, account, policy)
		})
	}
	stored, err := this.RestoreFromSession(req.Context(), sess, nil)
	if err != nil {
		return nil, err
	}
	auth := stored.(*local)
	auth.remote = req.Connection().Remote()
	setAuthorizationContext(req, auth)
	policy, accepted, err := evaluatePublicKeyCredential(key, req.Connection().Remote().User(), req.Connection().Remote().Host(), this.trustedUserCAs, func(consumer func(ssh.PublicKey, []crypto.AuthorizedKeyOption) (bool, error)) error {
		files, err := common.MapSliceErr(this.conf.AuthorizedKeys, func(tmpl template.String) (string, error) {
			return tmpl.Render(&localUserRequest{Request: req, user: auth.user})
		})
		if err != nil {
			return err
		}
		_, err = crypto.DoWithEachAuthorizedKey[bool](false, func(candidate ssh.PublicKey, options []crypto.AuthorizedKeyOption) (bool, bool, error) {
			cont, err := consumer(candidate, options)
			return !cont, cont, err
		}, files...)
		return err
	}, time.Now())
	if err != nil {
		return nil, err
	}
	if !accepted {
		return nil, ErrSessionResumeDenied
	}
	auth.authorizedKeyPolicy = policy
	return finishSessionResume(req, auth)
}

type windowsPasswordAccountCheck func(context.Context, windowslocal.Account, windowslocal.PasswordAccountPolicy) (windowslocal.PasswordAccountView, error)

func (this *LocalAuthorizer) resumeWindowsPasswordAccount(req SessionResumeRequest, sess session.Session, nativeCheck windowsPasswordAccountCheck) (Authorization, error) {
	if this.conf == nil || nativeCheck == nil {
		return nil, ErrSessionResumeUnavailable
	}
	raw, err := sess.AuthorizationToken(req.Context())
	if err != nil {
		return nil, err
	}
	// Only the original immutable account selector is restored, never historical
	// groups, profile/environment data or another connection's key policy.
	var selector struct {
		User struct {
			Name string `json:"name"`
			SID  string `json:"sid"`
		} `json:"user"`
	}
	if json.Unmarshal(raw, &selector) != nil || selector.User.Name == "" || selector.User.SID == "" {
		return nil, ErrSessionResumeDenied
	}
	selected := windowslocal.Account{Name: selector.User.Name, SID: selector.User.SID}
	check := func(allowEmpty bool) (windowslocal.PasswordAccountView, error) {
		current, err := nativeCheck(req.Context(), selected, windowslocal.PasswordAccountPolicy{AllowEmpty: allowEmpty})
		if contextErr := req.Context().Err(); contextErr != nil {
			return nil, errors.Join(err, contextErr)
		}
		if errors.Is(err, windowslocal.ErrPasswordAccountPolicyUnavailable) {
			return nil, ErrSessionResumeUnavailable
		}
		if errors.Is(err, windowslocal.ErrPasswordAccountPolicyDenied) {
			return nil, ErrSessionResumeDenied
		}
		if err != nil {
			return nil, err
		}
		if current == nil {
			return nil, ErrSessionResumeUnavailable
		}
		account := current.Account()
		if account.SID != selected.SID || !strings.EqualFold(account.Name, selected.Name) {
			return nil, ErrSessionResumeDenied
		}
		return current, nil
	}
	current, err := check(true)
	if err != nil {
		return nil, err
	}
	auth := &local{user: current.Account(), passwordAccount: current, remote: req.Connection().Remote(), flow: this.flow, session: sess}
	// This view belongs only to the validation below. The returned authorization
	// lives in a web access grant and must use the normal fresh native getters
	// for subsequent admissions, not retain this request's groups/profile data.
	defer func() { auth.passwordAccount = nil }()
	setAuthorizationContext(req, auth)
	allowed := this.conf.Password.Allowed
	if req.ResumeCredential().Method == "keyboard-interactive" {
		allowed = this.conf.Password.InteractiveAllowed
	}
	if ok, err := allowed.Render(req); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrSessionResumeDenied
	}
	allowEmpty, err := this.conf.Password.EmptyAllowed.Render(req)
	if err != nil {
		return nil, err
	}
	if _, err := finishSessionResume(req, auth); err != nil {
		return nil, err
	}
	checked, err := check(allowEmpty)
	if err != nil {
		return nil, err
	}
	if !current.IsEqualTo(checked) {
		return nil, fmt.Errorf("native Windows account changed during policy validation: %w", ErrSessionResumeDenied)
	}
	freshSession, err := req.Sessions().FindBy(req.Context(), sess.Flow(), sess.Id(), nil)
	if err != nil {
		return nil, err
	}
	if valid, err := session.IsStillValid(req.Context(), freshSession); err != nil {
		return nil, err
	} else if !valid {
		return nil, ErrSessionResumeDenied
	}
	auth.session = freshSession
	return auth, req.Context().Err()
}
