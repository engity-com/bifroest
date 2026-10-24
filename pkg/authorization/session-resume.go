package authorization

import (
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	ErrSessionResumeDenied      = berrors.User.Newf("session resumption denied")
	ErrSessionResumeUnavailable = errors.New("authorizer does not support verified session resumption")
)

// SessionResumeRequest is a trusted adapter capability AFTER fresh independent
// possession proof. None of these assertions may come from client JSON. The
// exact session, identity and original credential come from the stored binding.
type SessionResumeRequest interface {
	Request
	SessionPossessionVerified() bool
	SessionToResume() session.Session
	ResumeIdentity() authentication.Identity
	ResumeCredential() authentication.SessionCredential
}

// SessionResumer is optional; legacy/third-party authorizers do not implicitly
// become browser-resumable through their diagnostic RestoreFromSession method.
type SessionResumer interface {
	ResumeSession(SessionResumeRequest) (Authorization, error)
}

const FlowAuthorizationMethodBrowserRememberMe FlowAuthorizationMethod = "browser-remember-me"

func (this *AuthorizerFacade) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	if req == nil || !req.SessionPossessionVerified() || req.SessionToResume() == nil || req.ResumeIdentity().Validate() != nil || req.ResumeCredential().Validate() != nil {
		return nil, ErrSessionResumeDenied
	}
	selection, candidates, err := this.candidatesFor(req)
	if err != nil {
		return nil, err
	}
	if selection.Transport != connection.TransportHttp {
		return nil, ErrSessionResumeDenied
	}
	for _, candidate := range candidates {
		if candidate.flow != req.SessionToResume().Flow() {
			continue
		}
		allowed, err := candidate.canHandle(req, selection)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrSessionResumeDenied
		}
		resumer, ok := candidate.CloseableAuthorizer.(SessionResumer)
		if !ok {
			return nil, ErrSessionResumeUnavailable
		}
		auth, err := resumer.ResumeSession(req)
		if err == nil && auth != nil && auth.IsAuthorized() {
			if auth.Flow() != candidate.flow || auth.FindSession() == nil || auth.FindSession().Id() != req.SessionToResume().Id() || KindOf(auth) != req.ResumeCredential().Kind {
				err = ErrSessionResumeDenied
			} else if identity, identityErr := AuthenticationOf(auth); identityErr != nil || !sameResumeIdentity(identity, req.ResumeIdentity()) {
				err = ErrSessionResumeDenied
			}
		} else if err == nil {
			err = ErrSessionResumeDenied
		}
		if auditErr := this.observe(req, candidate.flow, FlowAuthorizationMethodBrowserRememberMe, FlowAuthorizationPhaseVerified, auth, err); auditErr != nil {
			return nil, auditErr
		}
		if err != nil {
			return nil, err
		}
		return auth, nil // Never fall through to a different flow or session.
	}
	return nil, ErrSessionResumeDenied
}

func sameResumeIdentity(actual, expected authentication.Identity) bool {
	if actual.Validate() != nil || expected.Validate() != nil {
		return false
	}
	if !actual.IsAuthenticated() || !expected.IsAuthenticated() {
		return actual == authentication.Anonymous() && expected == authentication.Anonymous()
	}
	return actual.SameSubject(expected)
}

func beginSessionResume(req SessionResumeRequest, kind string, flow configuration.FlowName) (session.Session, ssh.PublicKey, error) {
	if req == nil || !req.SessionPossessionVerified() || req.SessionToResume() == nil || req.ResumeIdentity().Validate() != nil {
		return nil, nil, ErrSessionResumeDenied
	}
	credential := req.ResumeCredential()
	if credential.Validate() != nil || credential.Kind != kind {
		return nil, nil, ErrSessionResumeDenied
	}
	if req.SessionToResume().Flow() != flow {
		return nil, nil, ErrSessionResumeDenied
	}
	selection, err := connection.SelectionOf(req)
	if err != nil || selection.Transport != connection.TransportHttp {
		return nil, nil, ErrSessionResumeDenied
	}
	if err := req.Context().Err(); err != nil {
		return nil, nil, err
	}
	old := req.SessionToResume()
	current, err := req.Sessions().FindBy(req.Context(), old.Flow(), old.Id(), nil)
	if err != nil {
		return nil, nil, err
	}
	if valid, err := session.IsStillValid(req.Context(), current); err != nil {
		return nil, nil, err
	} else if !valid {
		return nil, nil, ErrSessionResumeDenied
	}
	if credential.Method != "public-key" {
		return current, nil, nil
	}
	raw, _ := base64.StdEncoding.Strict().DecodeString(credential.PublicKey)
	key, err := ssh.ParsePublicKey(raw)
	if err != nil || base64.StdEncoding.EncodeToString(key.Marshal()) != credential.PublicKey {
		return nil, nil, ErrSessionResumeDenied
	}
	return current, key, nil
}

func finishSessionResume(req SessionResumeRequest, auth Authorization) (Authorization, error) {
	identity, err := AuthenticationOf(auth)
	if err != nil || !sameResumeIdentity(identity, req.ResumeIdentity()) {
		return nil, ErrSessionResumeDenied
	}
	if accepted, err := req.Validate(auth); err != nil {
		return nil, err
	} else if !accepted {
		return nil, ErrSessionResumeDenied
	}
	return auth, req.Context().Err()
}

type resumePublicKeyRequest struct {
	Request
	key ssh.PublicKey
}

func (this resumePublicKeyRequest) RemotePublicKey() ssh.PublicKey { return this.key }

// Deliberately no PublicKeyVerified assertion: the browser proved its OWN key,
// not a new signature with the original primary credential. Only eligibility
// helpers may consume this request; never invoke a primary login with it.
