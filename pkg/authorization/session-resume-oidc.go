package authorization

import (
	"context"
	"encoding/json"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func (this *OidcDeviceAuthAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "oidc-device-auth", this.flow)
	if err != nil {
		return nil, err
	}
	if req.ResumeCredential().Method == "password" {
		return nil, ErrSessionResumeDenied
	}
	if key != nil {
		if _, cert := key.(*ssh.Certificate); cert {
			return nil, ErrSessionResumeDenied
		}
		remembered, err := sess.HasPublicKey(req.Context(), key)
		if err != nil {
			return nil, err
		}
		if !remembered {
			return nil, ErrSessionResumeDenied
		}
	}
	auth, _, err := this.restoreSessionAccess(req.Context(), req, sess, key)
	if err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, ErrSessionResumeDenied
	}
	return auth, nil // The shared restore path validates current claims/environment.
}

// Used only AFTER verified SSH possession or a verified browser binding. It
// restores the pinned session's own rotating chain under the existing lock,
// handles Pending/loss exactly once, and never allocates/selects a new session.
func (this *OidcDeviceAuthAuthorizer) restoreSessionAccess(ctx context.Context, req Request, candidate session.Session, key ssh.PublicKey) (*oidc, *oidcToken, error) {
	unlock, err := this.lockSession(ctx, candidate)
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	at, err := candidate.AuthorizationToken(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(at) == 0 {
		return nil, nil, nil
	}
	var token oidcToken
	if err := json.Unmarshal(at, &token); err != nil {
		return nil, nil, err
	}
	if token.Token == nil || token.AccessToken == "" {
		return nil, nil, nil
	}
	if resume, ok := req.(SessionResumeRequest); ok && !oidcTokenHasIdentity(&token, resume.ResumeIdentity()) {
		return nil, nil, ErrSessionResumeDenied
	}
	if this.conf != nil && this.conf.RefreshEnabled() && this.conf.ForceDisposeSessionOn != "never" && !token.LastVerifiedAt.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, token.LastVerifiedAt.Add(this.maxUnverifiedFor()))
		defer cancel()
	}
	refresh := func(force bool) (bool, error) {
		if _, lost, err := this.refreshSession(ctx, candidate, &token, force); lost {
			if this.OnLostAccess != nil {
				this.OnLostAccess(candidate)
			}
			return false, nil
		} else if err != nil {
			return false, err
		}
		updated, err := this.readSessionToken(ctx, candidate)
		if err != nil {
			return false, err
		}
		token = *updated
		return true, nil
	}
	if token.Pending != nil {
		if ok, err := refresh(false); err != nil || !ok {
			return nil, nil, err
		}
	}
	if this.conf != nil && this.conf.ForceDisposeSessionOn != "never" && (token.Expiry.IsZero() || time.Now().Before(token.Expiry)) {
		if ok, err := refresh(false); err != nil || !ok {
			return nil, nil, err
		}
	}
	if !token.Expiry.IsZero() && !time.Now().Before(token.Expiry) {
		if this.conf == nil || !this.conf.RefreshEnabled() {
			return nil, nil, nil
		}
		if ok, err := refresh(true); err != nil || !ok {
			return nil, nil, err
		}
		if !token.Expiry.IsZero() && !time.Now().Before(token.Expiry) {
			return nil, nil, nil
		}
	}
	if this.conf != nil && this.conf.RefreshEnabled() && this.conf.RetrieveIdToken && token.IdToken != "" {
		if _, err := this.verifyToken(ctx, &token); errors.IsType(err, errors.Expired) {
			if ok, err := refresh(true); err != nil || !ok {
				return nil, nil, err
			}
		}
	}
	if !token.Expiry.IsZero() && !time.Now().Before(token.Expiry) {
		return nil, nil, nil
	}
	auth, err := this.finalizeAuth(ctx, req.Connection().Logger(), &token, true)
	if errors.IsType(err, errors.Expired) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	auth.remote = req.Connection().Remote()
	auth.session = candidate
	auth.sessionsPublicKey = key
	if resume, ok := req.(SessionResumeRequest); ok && !sameResumeIdentity(auth.identity, resume.ResumeIdentity()) {
		return nil, nil, ErrSessionResumeDenied
	}
	if accepted, err := req.Validate(auth); err != nil || !accepted {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := this.updateSessionWith(ctx, &token, candidate); err != nil {
		return nil, nil, err
	}
	return auth, &token, nil
}
