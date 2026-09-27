//go:build windows

package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
)

type LocalRepository struct {
	flow configuration.FlowName
	conf *configuration.EnvironmentLocal

	Logger log.Logger
}

func NewLocalRepository(_ context.Context, flow configuration.FlowName, conf *configuration.EnvironmentLocal, _ alternatives.Provider, _ imp.Imp) (*LocalRepository, error) {
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

func (this *LocalRepository) DoesSupportPty(_ Context, pty essh.Pty) (bool, error) {
	w := pty.Window
	return w.Width > 0 && w.Width <= 32767 && w.Height > 0 && w.Height <= 32767 &&
		windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find() == nil, nil
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

	name, err := this.conf.Name.Render(req)
	if err != nil {
		return failf(errors.Config, "cannot evaluate local account name: %w", err)
	}
	account, err := lookupLocalWindowsAccount(name)
	if err != nil {
		return failf(errors.Config, "invalid local account: %w", err)
	}
	if existing, err := this.FindBySession(req.Context(), sess, nil); err == nil {
		if current := existing.(*local).user; !strings.EqualFold(current.Name, account.Name) || current.SID != account.SID {
			return failf(errors.Expired, "local account identity changed for existing session")
		}
		return existing, nil
	} else if !errors.Is(err, ErrNoSuchEnvironment) {
		return fail(err)
	}

	lt, err := this.newLocalToken(req, account)
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

	return this.new(account, sess, portForwardingAllowed), nil
}

func (this *LocalRepository) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
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
	if lt.User.Name == "" || lt.User.SID == "" {
		return this.expireLocalToken(ctx, sess, opts)
	}
	account, err := lookupLocalWindowsAccount(lt.User.Name)
	if err != nil && !errors.Is(err, errLocalWindowsAccountNotFound) {
		return failf(errors.System, "cannot resolve session's local account: %w", err)
	}
	if err != nil || account.SID != lt.User.SID {
		return this.expireLocalToken(ctx, sess, opts)
	}

	return this.new(account, sess, lt.PortForwardingAllowed), nil
}

func (this *LocalRepository) expireLocalToken(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	if opts.IsAutoCleanUpAllowed() {
		if err := sess.SetEnvironmentToken(ctx, nil); err != nil {
			return nil, errors.System.Newf("cannot clear expired local account token: %w", err)
		}
		return nil, ErrNoSuchEnvironment
	}
	return nil, errors.Expired.Newf("local account of session no longer exists or changed SID")
}

func (this *LocalRepository) IsSessionCompatible(ctx context.Context, sess session.Session) (bool, error) {
	token, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return false, err
	}
	if len(token) == 0 {
		return true, nil
	}
	var stored localToken
	if err := json.Unmarshal(token, &stored); err != nil || stored.User.Name == "" || stored.User.SID == "" {
		return false, nil
	}
	account, err := lookupLocalWindowsAccount(stored.User.Name)
	if err != nil && !errors.Is(err, errLocalWindowsAccountNotFound) {
		return false, err
	}
	return err == nil && account.SID == stored.User.SID, nil
}

func (this *LocalRepository) IsSessionCompatibleWith(ctx Context, sess session.Session) (bool, error) {
	compatible, err := this.IsSessionCompatible(ctx.Context(), sess)
	if err != nil || !compatible {
		return compatible, err
	}
	name, err := this.conf.Name.Render(ctx)
	if err != nil {
		return false, err
	}
	account, err := lookupLocalWindowsAccount(name)
	if err != nil && !errors.Is(err, errLocalWindowsAccountNotFound) {
		return false, err
	}
	if err != nil {
		return false, nil
	}
	stored, err := sess.EnvironmentToken(ctx.Context())
	if err != nil {
		return false, err
	}
	if len(stored) == 0 {
		return true, nil
	}
	var token localToken
	if err := json.Unmarshal(stored, &token); err != nil {
		return false, nil
	}
	return strings.EqualFold(account.Name, token.User.Name) && account.SID == token.User.SID, nil
}

func (this *LocalRepository) Close() error {
	return nil
}
