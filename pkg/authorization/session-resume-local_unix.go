//go:build unix

package authorization

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "local", this.flow)
	if err != nil {
		return nil, err
	}
	// PAM and native logon policy require their own verified adapters. Ordinary
	// repository lookup/diagnostic restoration cannot substitute for them.
	if key == nil {
		if this.conf == nil || this.conf.PamService != "" {
			return nil, ErrSessionResumeUnavailable
		}
		if _, supported := this.userRepository.(user.PasswordAccountPolicyChecker); !supported {
			return nil, ErrSessionResumeUnavailable
		}
		return this.resumeRepositoryPasswordAccount(req, sess)
	}
	stored, err := this.RestoreFromSession(req.Context(), sess, nil)
	if err != nil {
		return nil, err
	}
	auth := stored.(*local)
	raw, err := sess.AuthorizationToken(req.Context())
	if err != nil {
		return nil, err
	}
	var token localToken
	if json.Unmarshal(raw, &token) != nil || token.User.Uid == nil || *token.User.Uid != auth.user.Uid {
		return nil, ErrSessionResumeDenied
	}
	auth.remote = req.Connection().Remote()
	setAuthorizationContext(req, auth)
	policy, accepted, _, err := this.authorizedKeyPolicy(resumePublicKeyRequest{req, key}, auth.user)
	if err != nil {
		return nil, err
	}
	if !accepted {
		return nil, ErrSessionResumeDenied
	}
	auth.authorizedKeyPolicy = policy
	// Public-key login never obtains PAM environment. A shared session may have
	// been created by password login, but its historical environment is not this
	// connection's authority or environment source.
	auth.envVars = nil
	return finishSessionResume(req, auth)
}

func (this *LocalAuthorizer) resumeRepositoryPasswordAccount(req SessionResumeRequest, sess session.Session) (Authorization, error) {
	raw, err := sess.AuthorizationToken(req.Context())
	if err != nil {
		return nil, err
	}
	// Decode only the immutable account selector. Never restore historical PAM
	// environment, rights or another connection's public-key policy.
	var token struct {
		User localTokenUser `json:"user"`
	}
	if json.Unmarshal(raw, &token) != nil || token.User.Name == "" || token.User.Uid == nil {
		return nil, ErrSessionResumeDenied
	}
	check := func(allowEmpty bool) (*user.User, error) {
		current, err := user.CheckPasswordAccount(req.Context(), this.userRepository, token.User.Name, *token.User.Uid, user.PasswordAccountPolicy{AllowEmpty: allowEmpty})
		if errors.Is(err, user.ErrPasswordAccountPolicyUnavailable) {
			return nil, ErrSessionResumeUnavailable
		}
		if errors.Is(err, user.ErrPasswordAccountPolicyDenied) {
			return nil, ErrSessionResumeDenied
		}
		return current, err
	}
	// This preliminary read grants nothing: policy templates must see current
	// identity/groups before deciding whether the primary method is still allowed.
	current, err := check(true)
	if err != nil {
		return nil, err
	}
	auth := &local{user: current, remote: req.Connection().Remote(), flow: this.flow, session: sess}
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
	// Recheck after template/environment validation, for both empty-password
	// policy values. A changed account must not escape through the earlier read.
	checked, err := check(allowEmpty)
	if err != nil {
		return nil, err
	}
	if !current.IsEqualTo(checked) {
		return nil, fmt.Errorf("native account changed during policy validation: %w", ErrSessionResumeDenied)
	}
	return auth, req.Context().Err()
}
