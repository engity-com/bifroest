//go:build unix

package authorization

import "encoding/json"

func (this *LocalAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "local", this.flow)
	if err != nil {
		return nil, err
	}
	// A UID lookup does not prove current PAM/account eligibility, nor does it
	// refresh PAM-provided environment. Until that secretless account check has
	// a verified native adapter, do not reuse password/interactive snapshots.
	if key == nil {
		return nil, ErrSessionResumeUnavailable
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
