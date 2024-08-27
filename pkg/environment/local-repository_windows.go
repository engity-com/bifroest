//go:build windows

package environment

import (
	"context"
	"encoding/json"
	"fmt"

	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

type LocalRepository struct {
	flow configuration.FlowName
	conf *configuration.EnvironmentLocal

	Logger log.Logger
}

func NewLocalRepository(_ context.Context, flow configuration.FlowName, conf *configuration.EnvironmentLocal) (*LocalRepository, error) {
	fail := func(err error) (*LocalRepository, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*LocalRepository, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	result := LocalRepository{
		flow: flow,
		conf: conf,
	}

	return &result, nil
}

func (this *LocalRepository) DoesSupportPty(Request, ssh.Pty) (bool, error) {
	return false, nil
}

func (this *LocalRepository) Ensure(req Request) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	if ok, err := this.WillBeAccepted(req); err != nil {
		return fail(err)
	} else if !ok {
		return fail(ErrNotAcceptable)
	}

	sess := req.Authorization().FindSession()
	if sess == nil {
		return failf(errors.System, "authorization without session")
	}

	if existing, err := this.FindBySession(req.Context(), sess, nil); err != nil {
		if !errors.Is(err, ErrNoSuchEnvironment) {
			req.Logger().
				WithError(err).
				Warn("cannot restore environment from existing session; will create a new one")
		}
	} else {
		return existing, nil
	}

	lt, err := this.newLocalToken(req)
	if err != nil {
		return fail(err)
	}
	portForwardingAllowed, err := this.conf.PortForwardingAllowed.Render(req)
	if err != nil {
		return fail(err)
	}
	if ltb, err := json.Marshal(lt); err != nil {
		return failf(errors.System, "cannot marshal environment token: %w", err)
	} else if err := sess.SetEnvironmentToken(req.Context(), ltb); err != nil {
		return failf(errors.System, "cannot store environment token at session: %w", err)
	}

	return this.new(sess, portForwardingAllowed), nil
}

func (this *LocalRepository) FindBySession(ctx context.Context, sess session.Session, _ *FindOpts) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	ltb, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return failf(errors.System, "cannot get environment token: %w", err)
	}
	if len(ltb) == 0 {
		return fail(ErrNoSuchEnvironment)
	}
	var lt localToken
	if err := json.Unmarshal(ltb, &lt); err != nil {
		return failf(errors.System, "cannot decode environment token: %w", err)
	}

	return this.new(sess, lt.PortForwardingAllowed), nil
}

func (this *LocalRepository) Close() error {
	return nil
}
