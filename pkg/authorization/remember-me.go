package authorization

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
)

// An explicitly configured key restriction cannot be bypassed via a remembered
// password login using that same key. Other flows may still evaluate it normally.
type configuredPublicKeyDenial struct{ Authorization }

// Block only remembered-key lookup, never ordinary configured public keys.
type withoutRememberedSessions struct{ session.Repository }

func (r withoutRememberedSessions) FindByPublicKey(context.Context, ssh.PublicKey, *session.FindOpts) (session.Session, error) {
	return nil, session.ErrNoSuchSession
}

type primaryPublicKeyRequest struct{ PublicKeyRequest }

func (r primaryPublicKeyRequest) Sessions() session.Repository {
	return withoutRememberedSessions{r.PublicKeyRequest.Sessions()}
}
func (r primaryPublicKeyRequest) PublicKeyVerified() bool {
	return isPublicKeyVerified(r.PublicKeyRequest)
}
func (r primaryPublicKeyRequest) Selection() connection.Selection {
	selection, _ := connection.SelectionOf(r.PublicKeyRequest)
	return selection
}
func (r primaryPublicKeyRequest) SetAuthorizationContext(a Authorization) {
	setAuthorizationContext(r.PublicKeyRequest, a)
}
func (r primaryPublicKeyRequest) GetField(name string) (any, bool, error) {
	if fields, ok := r.PublicKeyRequest.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return fields.GetField(name)
	}
	return nil, false, fmt.Errorf("authorization request field %q is unavailable", name)
}
func (r primaryPublicKeyRequest) ResolveAuthenticatedSession(a Authorization, token []byte) (session.Session, bool, error) {
	return resolveAuthenticatedSession(r.PublicKeyRequest, a, token)
}
func (r primaryPublicKeyRequest) ResolveAuthenticatedSessionWithReuse(a Authorization, token []byte, reuse session.Predicate) (session.Session, bool, error) {
	return resolveAuthenticatedSessionWithReuse(r.PublicKeyRequest, a, token, reuse)
}

type sshSessionResumeRequest struct {
	PublicKeyRequest
	sess   session.Session
	stored session.SSHRememberedCredential
}

func (r sshSessionResumeRequest) SessionPossessionVerified() bool {
	return isPublicKeyVerified(r.PublicKeyRequest)
}
func (r sshSessionResumeRequest) SessionToResume() session.Session        { return r.sess }
func (r sshSessionResumeRequest) ResumeIdentity() authentication.Identity { return r.stored.Identity }
func (r sshSessionResumeRequest) ResumeCredential() authentication.SessionCredential {
	return r.stored.Credential
}
func (r sshSessionResumeRequest) Selection() connection.Selection {
	selection, _ := connection.SelectionOf(r.PublicKeyRequest)
	return selection
}
func (r sshSessionResumeRequest) SetAuthorizationContext(a Authorization) {
	setAuthorizationContext(r.PublicKeyRequest, a)
}
func (r sshSessionResumeRequest) GetField(name string) (any, bool, error) {
	return (primaryPublicKeyRequest{r.PublicKeyRequest}).GetField(name)
}

func (a *LocalAuthorizer) authorizeRememberedSSH(req PublicKeyRequest) (Authorization, error) {
	var result Authorization
	_, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(a.flow), session.IsStillValid, session.IsRemoteName(req.Connection().Remote().User()),
		func(ctx context.Context, sess session.Session) (bool, error) {
			store, ok := sess.(session.SSHRememberMeSession)
			if !ok {
				return false, nil
			}
			stored, err := store.SSHKeyCredential(ctx, req.RemotePublicKey())
			if errors.Is(err, session.ErrNoSuchSession) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if stored.Credential.Kind != "local" || (stored.Credential.Method != "password" && stored.Credential.Method != "keyboard-interactive") {
				return false, nil
			}
			if !isPublicKeyVerified(req) {
				result = &local{flow: a.flow, remote: req.Connection().Remote(), session: sess}
				return true, nil
			}
			result, err = a.ResumeSession(sshSessionResumeRequest{req, sess, stored})
			if restored, ok := result.(*local); ok && err == nil {
				restored.sessionsPublicKey = req.RemotePublicKey()
			}
			if errors.Is(err, ErrSessionResumeDenied) || errors.Is(err, ErrSessionResumeUnavailable) {
				return false, nil
			}
			return err == nil && result != nil && result.IsAuthorized(), err
		},
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		return Forbidden(req.Connection().Remote()), nil
	}
	return result, err
}
