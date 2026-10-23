//go:build windows

package authorization

import (
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func (this *LocalAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "local", this.flow)
	if err != nil {
		return nil, err
	}
	// SID/account availability alone does not reproduce current LogonUser
	// restrictions (including denied network logon). Do not resume a password
	// snapshot until a secretless native account-policy adapter is available.
	if key == nil {
		return nil, ErrSessionResumeUnavailable
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
