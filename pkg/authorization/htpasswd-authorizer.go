package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	_ = RegisterAuthorizer(NewHtpasswd)
)

type HtpasswdAuthorizer struct {
	flow configuration.FlowName
	conf *configuration.AuthorizationHtpasswd

	Logger log.Logger
}

func NewHtpasswd(_ context.Context, flow configuration.FlowName, conf *configuration.AuthorizationHtpasswd) (*HtpasswdAuthorizer, error) {
	fail := func(err error) (*HtpasswdAuthorizer, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*HtpasswdAuthorizer, error) {
		return fail(errors.Newf(errors.Config, msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	result := HtpasswdAuthorizer{
		flow: flow,
		conf: conf,
	}

	return &result, nil
}

func (this *HtpasswdAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize htpasswd %q via authorized keys: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	sess, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		return Forbidden(req.Remote()), nil
	} else if err != nil {
		return failf("cannot find session: %w", err)
	}

	auth := &htpasswd{
		remote:            req.Remote(),
		envVars:           nil,
		flow:              this.flow,
		session:           sess,
		sessionsPublicKey: req.RemotePublicKey(),
	}

	if accepted, err := req.Validate(auth); err != nil {
		return nil, fmt.Errorf("cannot validate request: %w", err)
	} else if !accepted {
		return Forbidden(req.Remote()), nil
	}

	return auth, nil
}

func (this *HtpasswdAuthorizer) lookupEntry(req Request, password string) (auth *htpasswd, accepted bool, err error) {
	match := false
	if f := this.conf.File; !f.IsZero() {
		if f.Match(req.Remote().User(), password) {
			match = true
		}
	}

	if f := this.conf.Entries; !match && !f.IsZero() {
		if f.Match(req.Remote().User(), password) {
			match = true
		}
	}

	if !match {
		return nil, false, nil
	}

	auth = &htpasswd{
		req.Remote(),
		nil,
		this.flow,
		nil,
		nil,
	}

	accepted, err = req.Validate(auth)
	if err != nil {
		return nil, false, fmt.Errorf("cannot validate request: %w", err)
	}

	return auth, accepted, nil
}

func (this *HtpasswdAuthorizer) ensureSessionFor(req Request) (session.Session, error) {
	fail := func(err error) (session.Session, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (session.Session, error) {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	buf := htpasswdToken{
		User: htpasswdTokenUser{
			Name: req.Remote().User(),
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
		session.IsRemoteName(req.Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		sess, err = req.Sessions().Create(req.Context(), this.flow, req.Remote(), at)
	}
	if err != nil {
		return fail(err)
	}

	return sess, nil
}

func (this *HtpasswdAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize htpasswd %q via password: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	auth, accepted, err := this.lookupEntry(req, req.RemotePassword())
	if err != nil {
		return fail(err)
	}
	if !accepted {
		return Forbidden(req.Remote()), nil
	}

	sess, err := this.ensureSessionFor(req)
	if err != nil {
		return failf("cannot create session: %w", err)
	}
	auth.session = sess

	return auth, nil
}

func (this *HtpasswdAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize htpasswd %q via password: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	pass, err := req.Prompt("Password: ", false)
	if err != nil {
		return fail(err)
	}

	auth, accepted, err := this.lookupEntry(req, pass)
	if err != nil {
		return fail(err)
	}
	if !accepted {
		return Forbidden(req.Remote()), nil
	}

	sess, err := this.ensureSessionFor(req)
	if err != nil {
		return failf("cannot create session: %w", err)
	}
	auth.session = sess

	return auth, nil
}

func (this *HtpasswdAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, _ *RestoreOpts) (Authorization, error) {
	failf := func(t errors.Type, msg string, args ...any) (Authorization, error) {
		args = append([]any{sess}, args...)
		return nil, errors.Newf(t, "cannot restore authorization from session %v: "+msg, args...)
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

	var buf htpasswdToken
	if err := json.Unmarshal(tb, &buf); err != nil {
		return failf(errors.System, "cannot decode token of: %w", err)
	}

	si, err := sess.Info(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve session's info: %w", err)
	}
	sla, err := si.LastAccessed(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve session's last accessed: %w", err)
	}

	return &htpasswd{
		sla.Remote(),
		buf.EnvVars.Clone(),
		this.flow.Clone(),
		sess,
		nil,
	}, nil
}

func (this *HtpasswdAuthorizer) Close() error {
	return nil
}

func (this *HtpasswdAuthorizer) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("authorizer")
}
