//go:build unix

package authorization

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "local", this.flow)
	if err != nil {
		return nil, err
	}
	if this.conf == nil {
		return nil, ErrSessionResumeUnavailable
	}
	// Ordinary lookup/diagnostic restoration cannot substitute for fresh native
	// policy. PAM account-only resumption additionally requires explicit opt-in.
	if key == nil {
		if this.conf == nil {
			return nil, ErrSessionResumeUnavailable
		}
		if _, supported := this.userRepository.(user.PasswordAccountPolicyChecker); !supported {
			return nil, ErrSessionResumeUnavailable
		}
		if this.conf.PamService != "" {
			if !this.conf.PamAccountResumeAllowed {
				return nil, ErrSessionResumeUnavailable
			}
			return this.resumePasswordAccount(req, sess, func(name string, id user.Id, policy user.PasswordAccountPolicy) (*user.User, sys.EnvVars, error) {
				return this.checkPamPasswordAccount(req, name, id, policy)
			})
		}
		return this.resumePasswordAccount(req, sess, func(name string, id user.Id, policy user.PasswordAccountPolicy) (*user.User, sys.EnvVars, error) {
			current, err := user.CheckPasswordAccount(req.Context(), this.userRepository, name, id, policy)
			return current, nil, err
		})
	}
	stored, err := this.RestoreFromSession(req.Context(), sess, nil)
	if err != nil {
		return nil, err
	}
	auth := stored.(*local)
	remoteName, err := this.resumeRemoteName(req, sess, auth.user)
	if err != nil {
		return nil, err
	}
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
	policy, accepted, _, err := this.authorizedKeyPolicy(resumePublicKeyRequest{req, key}, auth.user, remoteName)
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

type passwordResumeCheck func(string, user.Id, user.PasswordAccountPolicy) (*user.User, sys.EnvVars, error)

func (this *LocalAuthorizer) resumeRemoteName(req Request, sess session.Session, expected *user.User) (string, error) {
	name, err := resolveRemoteName(req, this.conf.RemoteName)
	if err != nil {
		return "", err
	}
	custom := hasRemoteNameMapping(this.conf.RemoteName)
	if !custom && (name == "" || name == expected.Name) {
		return name, nil
	}
	if err := checkMappedResumeRemote(req, sess, this.conf.RemoteName); err != nil {
		return "", err
	}
	current, err := this.userRepository.LookupByName(req.Context(), name)
	if errors.Is(err, user.ErrNoSuchUser) {
		return "", ErrSessionResumeDenied
	}
	if err != nil {
		return "", err
	}
	if current == nil || current.Name != expected.Name || current.Uid != expected.Uid {
		return "", ErrSessionResumeDenied
	}
	return name, nil
}

func (this *LocalAuthorizer) resumePasswordAccount(req SessionResumeRequest, sess session.Session, nativeCheck passwordResumeCheck) (Authorization, error) {
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
	if _, err := this.resumeRemoteName(req, sess, &user.User{Name: token.User.Name, Uid: *token.User.Uid}); err != nil {
		return nil, err
	}
	check := func(allowEmpty bool) (*user.User, sys.EnvVars, error) {
		current, env, err := nativeCheck(token.User.Name, *token.User.Uid, user.PasswordAccountPolicy{AllowEmpty: allowEmpty})
		if errors.Is(err, user.ErrPasswordAccountPolicyUnavailable) {
			return nil, nil, ErrSessionResumeUnavailable
		}
		if errors.Is(err, user.ErrPasswordAccountPolicyDenied) {
			return nil, nil, ErrSessionResumeDenied
		}
		return current, env, err
	}
	// This preliminary read grants nothing: policy templates must see current
	// identity/groups before deciding whether the primary method is still allowed.
	current, env, err := check(true)
	if err != nil {
		return nil, err
	}
	auth := &local{user: current, envVars: env, remote: req.Connection().Remote(), flow: this.flow, session: sess}
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
	checked, checkedEnv, err := check(allowEmpty)
	if err != nil {
		return nil, err
	}
	if !current.IsEqualTo(checked) || !maps.Equal(env, checkedEnv) {
		return nil, fmt.Errorf("native account changed during policy validation: %w", ErrSessionResumeDenied)
	}
	return auth, req.Context().Err()
}
