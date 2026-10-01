//go:build windows

package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

var _ = RegisterAuthorizer(NewLocal)

type LocalAuthorizer struct {
	flow           configuration.FlowName
	conf           *configuration.AuthorizationLocal
	trustedUserCAs []ssh.PublicKey
}

func NewLocal(_ context.Context, flow configuration.FlowName, conf *configuration.AuthorizationLocal) (*LocalAuthorizer, error) {
	if conf == nil {
		return nil, errors.Config.Newf("nil local authorization configuration")
	}
	if err := conf.Validate(); err != nil {
		return nil, errors.Config.Newf("invalid local authorization: %w", err)
	}
	cas, err := loadTrustedUserCAs(&conf.UserCertificateAuthorityProperties)
	if err != nil {
		return nil, errors.Config.Newf("cannot load trusted user CAs: %w", err)
	}
	return &LocalAuthorizer{flow: flow, conf: conf, trustedUserCAs: cas}, nil
}

func (*LocalAuthorizer) SupportsUserCertificates() {}
func (*LocalAuthorizer) Close() error              { return nil }

func (this *LocalAuthorizer) lookupActive(name string) (windowslocal.Account, bool, error) {
	if name == "" {
		return windowslocal.Account{}, false, nil
	}
	u, err := windowslocal.Lookup(name)
	if errors.Is(err, windowslocal.ErrNotFound) {
		return u, false, nil
	}
	if err != nil {
		return u, false, err
	}
	unavailable, err := windowslocal.Unavailable(u)
	if errors.Is(err, windowslocal.ErrNotFound) {
		return u, false, nil
	}
	return u, !unavailable && err == nil, err
}

func (this *LocalAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	remote := req.Connection().Remote()
	if len(this.conf.AuthorizedKeys) == 0 && len(this.trustedUserCAs) == 0 {
		return Forbidden(remote), nil
	}
	u, found, err := this.lookupActive(remote.User())
	if err != nil {
		return nil, fmt.Errorf("cannot lookup local user: %w", err)
	}
	if !found {
		return Forbidden(remote), nil
	}
	candidate := &local{user: u, remote: remote, flow: this.flow}
	if ok, err := req.Validate(candidate); err != nil {
		return nil, fmt.Errorf("cannot validate local request: %w", err)
	} else if !ok {
		return Forbidden(remote), nil
	}
	policy, accepted, err := evaluatePublicKeyCredential(req.RemotePublicKey(), remote.User(), remote.Host(), this.trustedUserCAs,
		func(consumer func(ssh.PublicKey, []crypto.AuthorizedKeyOption) (bool, error)) error {
			files, err := common.MapSliceErr(this.conf.AuthorizedKeys, func(tmpl template.String) (string, error) {
				return tmpl.Render(&localUserRequest{Request: req, user: u})
			})
			if err != nil {
				return fmt.Errorf("cannot render authorizedKeys: %w", err)
			}
			_, err = crypto.DoWithEachAuthorizedKey[bool](false, func(key ssh.PublicKey, options []crypto.AuthorizedKeyOption) (bool, bool, error) {
				cont, err := consumer(key, options)
				return !cont, cont, err
			}, files...)
			return err
		}, time.Now())
	if err != nil {
		return nil, fmt.Errorf("cannot evaluate local authorized keys: %w", err)
	}
	if !accepted {
		return Forbidden(remote), nil
	}
	candidate.authorizedKeyPolicy = policy
	if _, isCert := req.RemotePublicKey().(*ssh.Certificate); isCert {
		if !isPublicKeyVerified(req) {
			return candidate, nil
		}
		candidate.session, err = this.ensureSessionFor(req, u)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	}
	sess, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow), session.IsStillValid, session.IsRemoteName(remote.User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		sess = nil
	} else if err != nil {
		return nil, fmt.Errorf("cannot find local session: %w", err)
	}
	if sess != nil {
		matches, err := localSessionMatches(req.Context(), sess, u)
		if err != nil {
			return nil, err
		}
		if matches {
			candidate.session = sess
			candidate.sessionsPublicKey = req.RemotePublicKey()
			return candidate, nil
		}
	}
	candidate.session, err = this.ensureSessionFor(req, u)
	if err != nil {
		return nil, err
	}
	return candidate, nil
}

type localUserRequest struct {
	Request
	user windowslocal.Account
}

func (this *localUserRequest) GetField(name string) (any, bool) {
	if name == "user" {
		return this.user, true
	}
	return nil, false
}

func localSessionMatches(ctx context.Context, sess session.Session, u windowslocal.Account) (bool, error) {
	b, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return false, err
	}
	var token localToken
	if err := json.Unmarshal(b, &token); err != nil {
		return false, nil
	}
	return token.User.SID == u.SID && strings.EqualFold(token.User.Name, u.Name), nil
}

func (this *LocalAuthorizer) ensureSessionFor(req Request, u windowslocal.Account) (session.Session, error) {
	var token localToken
	token.User.Name, token.User.SID = u.Name, u.SID
	b, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	sess, err := req.Sessions().FindByAccessToken(req.Context(), b, (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow), session.IsStillValid, session.IsRemoteName(req.Connection().Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		return req.Sessions().Create(req.Context(), this.flow, req.Connection().Remote(), b)
	}
	return sess, err
}

func (this *LocalAuthorizer) authorizePassword(req Request, value string, allowed template.Bool) (Authorization, error) {
	remote := req.Connection().Remote()
	ok, err := allowed.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot evaluate password permission: %w", err)
	}
	if !ok {
		return Forbidden(remote), nil
	}
	if value == "" {
		ok, err = this.conf.Password.EmptyAllowed.Render(req)
		if err != nil {
			return nil, fmt.Errorf("cannot evaluate empty password permission: %w", err)
		}
		if !ok {
			return Forbidden(remote), nil
		}
	}
	u, found, err := this.lookupActive(remote.User())
	if err != nil {
		return nil, fmt.Errorf("cannot lookup local user: %w", err)
	}
	if !found {
		return Forbidden(remote), nil
	}
	ok, err = windowslocal.ValidatePassword(u, value)
	if errors.Is(err, windowslocal.ErrNotFound) {
		return Forbidden(remote), nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot validate local password: %w", err)
	}
	if !ok {
		return Forbidden(remote), nil
	}
	candidate := &local{user: u, remote: remote, flow: this.flow}
	if ok, err := req.Validate(candidate); err != nil {
		return nil, fmt.Errorf("cannot validate local request: %w", err)
	} else if !ok {
		return Forbidden(remote), nil
	}
	candidate.session, err = this.ensureSessionFor(req, u)
	if err != nil {
		return nil, err
	}
	return candidate, nil
}

func (this *LocalAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	return this.authorizePassword(req, req.RemotePassword(), this.conf.Password.Allowed)
}

func (this *LocalAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	ok, err := this.conf.Password.InteractiveAllowed.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot evaluate interactive permission: %w", err)
	}
	if !ok {
		return Forbidden(req.Connection().Remote()), nil
	}
	pass, err := req.Prompt("Password: ", false)
	if err != nil {
		return nil, err
	}
	return this.authorizePassword(req, pass, this.conf.Password.InteractiveAllowed)
}

func (this *LocalAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, opts *RestoreOpts) (Authorization, error) {
	if !sess.Flow().IsEqualTo(this.flow) {
		return nil, ErrNoSuchAuthorization
	}
	b, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, ErrNoSuchAuthorization
	}
	var token localToken
	if err := json.Unmarshal(b, &token); err != nil || token.User.Name == "" || token.User.SID == "" {
		return nil, unusableAuthorizationToken(ctx, sess, opts, fmt.Errorf("invalid local authorization token: %v", err))
	}
	u, err := windowslocal.LookupBySID(token.User.SID)
	if errors.Is(err, windowslocal.ErrNotFound) || (err == nil && !strings.EqualFold(u.Name, token.User.Name)) {
		return nil, unusableAuthorizationToken(ctx, sess, opts, fmt.Errorf("local account no longer matches stored SID"))
	}
	if err != nil {
		return nil, err
	}
	unavailable, err := windowslocal.Unavailable(u)
	if errors.Is(err, windowslocal.ErrNotFound) || (err == nil && unavailable) {
		return nil, unusableAuthorizationToken(ctx, sess, opts, fmt.Errorf("local account is unavailable"))
	}
	if err != nil {
		return nil, err
	}
	info, err := sess.Info(ctx)
	if err != nil {
		return nil, err
	}
	last, err := info.LastAccessed(ctx)
	if err != nil {
		return nil, err
	}
	return &local{user: u, remote: last.Remote(), flow: this.flow.Clone(), session: sess}, nil
}
