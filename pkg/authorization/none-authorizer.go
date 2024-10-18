package authorization

import (
	"context"
	"fmt"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	_ = RegisterAuthorizer(NewNone)
)

type NoneAuthorizer struct {
	flow configuration.FlowName
	conf *configuration.AuthorizationNone

	Logger log.Logger
}

func NewNone(_ context.Context, flow configuration.FlowName, conf *configuration.AuthorizationNone) (*NoneAuthorizer, error) {
	fail := func(err error) (*NoneAuthorizer, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*NoneAuthorizer, error) {
		return fail(errors.Newf(errors.Config, msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	result := NoneAuthorizer{
		flow: flow,
		conf: conf,
	}

	return &result, nil
}

func (this *NoneAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize none %q via authorized keys: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	auth := &none{
		req.Remote(),
		nil,
		this.flow,
		nil,
		nil,
	}

	sess, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		sess, err = req.Sessions().Create(req.Context(), this.flow, req.Remote(), nil)
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

func (this *NoneAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize none %q via password: %w", req.Remote().User(), err)
	}

	sess, err := req.Sessions().Create(req.Context(), this.flow, req.Remote(), nil)
	if err != nil {
		return fail(err)
	}

	return &none{
		req.Remote(),
		nil,
		this.flow,
		sess,
		nil,
	}, nil
}

func (this *NoneAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize none %q via password: %w", req.Remote().User(), err)
	}

	sess, err := req.Sessions().Create(req.Context(), this.flow, req.Remote(), nil)
	if err != nil {
		return fail(err)
	}

	return &none{
		req.Remote(),
		nil,
		this.flow,
		sess,
		nil,
	}, nil
}

func (this *NoneAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, _ *RestoreOpts) (Authorization, error) {
	failf := func(t errors.Type, msg string, args ...any) (Authorization, error) {
		args = append([]any{sess}, args...)
		return nil, errors.Newf(t, "cannot restore authorization from session %v: "+msg, args...)
	}
	if !sess.Flow().IsEqualTo(this.flow) {
		return nil, ErrNoSuchAuthorization
	}

	si, err := sess.Info(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve session's info: %w", err)
	}
	sla, err := si.LastAccessed(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve session's last accessed: %w", err)
	}

	return &none{
		sla.Remote(),
		nil,
		this.flow.Clone(),
		sess,
		nil,
	}, nil
}

func (this *NoneAuthorizer) Close() error {
	return nil
}

func (this *NoneAuthorizer) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("authorizer")
}
