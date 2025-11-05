package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/echocat/slf4g"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	_ = RegisterAuthorizer(NewSimple)
)

type SimpleAuthorizer struct {
	flow configuration.FlowName
	conf *configuration.AuthorizationSimple

	Logger log.Logger
}

func NewSimple(_ context.Context, flow configuration.FlowName, conf *configuration.AuthorizationSimple) (*SimpleAuthorizer, error) {
	fail := func(err error) (*SimpleAuthorizer, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*SimpleAuthorizer, error) {
		return fail(errors.Newf(errors.Config, msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	result := SimpleAuthorizer{
		flow: flow,
		conf: conf,
	}

	return &result, nil
}

func (this *SimpleAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize simple %q via authorized keys: %w", req.Connection().Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	entry, auth, accepted, err := this.lookupEntry(req)
	if err != nil {
		return fail(err)
	}
	if !accepted {
		return Forbidden(req.Connection().Remote()), nil
	}

	sess, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Connection().Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		if ok, err := this.isAuthorizedViaPublicKey(req, entry); err != nil {
			return fail(err)
		} else if !ok {
			return Forbidden(req.Connection().Remote()), nil
		}
		sess, err = this.ensureSessionFor(req, entry)
		if err != nil {
			return fail(err)
		}

		auth.session = sess
	} else if err != nil {
		return failf("cannot find session: %w", err)
	} else {
		auth.session = sess
		auth.sessionsPublicKey = req.RemotePublicKey()
	}

	return auth, nil
}

func (this *SimpleAuthorizer) lookupEntry(req Request) (entry *configuration.AuthorizationSimpleEntry, auth *simple, accepted bool, err error) {
	for _, candidate := range this.conf.Entries {
		if !strings.EqualFold(candidate.Name, req.Connection().Remote().User()) {
			continue
		}
		entry = &candidate
		break
	}

	if entry == nil {
		return nil, nil, false, nil
	}

	auth = &simple{
		entry,
		req.Connection().Remote(),
		nil,
		this.flow,
		nil,
		nil,
	}

	accepted, err = req.Validate(auth)
	if err != nil {
		return nil, nil, false, fmt.Errorf("cannot validate request: %w", err)
	}

	return entry, auth, accepted, nil
}

func (this *SimpleAuthorizer) isAuthorizedViaPublicKey(req PublicKeyRequest, entry *configuration.AuthorizationSimpleEntry) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, err
	}
	failf := func(msg string, args ...any) (bool, error) {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	foundMatch := false

	if v := entry.AuthorizedKeysFile; !v.IsZero() {
		if err := v.ForEach(func(_ int, key ssh.PublicKey, _ string, _ []crypto.AuthorizedKeyOption) (canContinue bool, err error) {
			if bytes.Equal(req.RemotePublicKey().Marshal(), key.Marshal()) {
				foundMatch = true
				return false, nil
			}
			return true, nil
		}); err != nil {
			return failf("cannot resolve authorized keys of user %q: %w", entry.Name, err)
		}
	}

	if !foundMatch {
		if v := entry.AuthorizedKeys; !v.IsZero() {
			if err := v.ForEach(func(_ int, key ssh.PublicKey, _ string, _ []crypto.AuthorizedKeyOption) (canContinue bool, err error) {
				if bytes.Equal(req.RemotePublicKey().Marshal(), key.Marshal()) {
					foundMatch = true
					return false, nil
				}
				return true, nil
			}); err != nil {
				return failf("cannot resolve authorized keys of user %q: %w", entry.Name, err)
			}
		}
	}

	if !foundMatch {
		req.Connection().Logger().Debug("presented public key does not match any authorized keys of simple user")
		return false, nil
	}

	return true, nil
}

func (this *SimpleAuthorizer) ensureSessionFor(req Request, entry *configuration.AuthorizationSimpleEntry) (session.Session, error) {
	fail := func(err error) (session.Session, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (session.Session, error) {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	buf := simpleToken{
		User: simpleTokenUser{
			Name: entry.Name,
		},
		EnvVars: nil,
	}
	at, err := json.Marshal(buf)
	if err != nil {
		return failf("cannot marshal authorization token: %w", err)
	}

	sess, err := req.Sessions().FindByAccessToken(req.Context(), at, (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Connection().Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		sess, err = req.Sessions().Create(req.Context(), this.flow, req.Connection().Remote(), at)
	}
	if err != nil {
		return fail(err)
	}

	return sess, nil
}

func (this *SimpleAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize simple %q via password: %w", req.Connection().Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	entry, auth, accepted, err := this.lookupEntry(req)
	if err != nil {
		return fail(err)
	}
	if !accepted {
		return Forbidden(req.Connection().Remote()), nil
	}

	if expected, err := entry.GetPassword(); err != nil {
		return failf("cannot get password of entry %q: %w", entry.Name, err)
	} else if expected.IsZero() {
		return Forbidden(req.Connection().Remote()), nil
	} else if ok, err := expected.Compare([]byte(req.RemotePassword())); err != nil || !ok {
		return Forbidden(req.Connection().Remote()), nil
	}

	sess, err := this.ensureSessionFor(req, entry)
	if err != nil {
		return failf("cannot create session: %w", err)
	}

	auth.session = sess

	return auth, nil
}

func (this *SimpleAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize simple %q via password: %w", req.Connection().Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	entry, auth, accepted, err := this.lookupEntry(req)
	if err != nil {
		return fail(err)
	}
	if !accepted {
		return Forbidden(req.Connection().Remote()), nil
	}

	pass, err := req.Prompt("Password: ", false)
	if err != nil {
		return fail(err)
	}

	if expected, err := entry.GetPassword(); err != nil {
		return failf("cannot get password of entry %q: %w", entry.Name, err)
	} else if expected.IsZero() {
		return Forbidden(req.Connection().Remote()), nil
	} else if ok, err := expected.Compare([]byte(pass)); err != nil || !ok {
		return Forbidden(req.Connection().Remote()), nil
	}

	sess, err := this.ensureSessionFor(req, entry)
	if err != nil {
		return failf("cannot create session: %w", err)
	}

	auth.session = sess

	return auth, nil
}

func (this *SimpleAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, opts *RestoreOpts) (Authorization, error) {
	failf := func(t errors.Type, msg string, args ...any) (Authorization, error) {
		args = append([]any{sess}, args...)
		return nil, errors.Newf(t, "cannot restore authorization from session %v: "+msg, args...)
	}
	cleanFromSessionOnly := func() (Authorization, error) {
		if opts.IsAutoCleanUpAllowed() {
			// Clear the stored token.
			if err := sess.SetAuthorizationToken(ctx, nil); err != nil {
				return failf(errors.System, "cannot clear existing authorization token of session after user wasn't found: %w", err)
			}
			opts.GetLogger(this.logger).
				With("session", sess).
				Info("session's user does not longer exist; therefore according authorization token was removed from session")
		}
		return nil, ErrNoSuchAuthorization
	}

	if !sess.Flow().IsEqualTo(this.flow) {
		return nil, ErrNoSuchAuthorization
	}

	tb, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve token: %w", err)
	}

	if len(tb) == 0 {
		return nil, ErrNoSuchAuthorization
	}

	var buf simpleToken
	if err := json.Unmarshal(tb, &buf); err != nil {
		return failf(errors.System, "cannot decode token of: %w", err)
	}

	var entry *configuration.AuthorizationSimpleEntry
	for _, candidate := range this.conf.Entries {
		if candidate.Name != buf.User.Name {
			continue
		}
		entry = &candidate
		break
	}

	if entry == nil {
		return cleanFromSessionOnly()
	}

	si, err := sess.Info(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve session's info: %w", err)
	}
	sla, err := si.LastAccessed(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve session's last accessed: %w", err)
	}

	return &simple{
		entry,
		sla.Remote(),
		buf.EnvVars.Clone(),
		this.flow.Clone(),
		sess,
		nil,
	}, nil
}

func (this *SimpleAuthorizer) Close() error {
	return nil
}

func (this *SimpleAuthorizer) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("authorizer")
}
