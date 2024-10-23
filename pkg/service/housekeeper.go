package service

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

type houseKeeper struct {
	service       *service
	closed        atomic.Bool
	contextCancel context.CancelFunc
}

func (this *houseKeeper) init(service *service) error {
	success := false
	this.service = service
	var ctx context.Context
	ctx, this.contextCancel = context.WithCancel(context.Background())
	defer common.DoIfFalse(&success, this.contextCancel)

	var nextRunIn time.Duration
	if initialDelay := this.service.Configuration.HouseKeeping.InitialDelay; initialDelay.IsZero() {
		var err error
		if nextRunIn, err = this.checkedRun(ctx); err != nil {
			return errors.Newf(errors.System, "initial house keeping run failed: %w", err)
		}
	} else {
		nextRunIn = initialDelay.Native()
	}

	go this.loop(ctx, nextRunIn)

	success = true

	return nil
}

func (this *houseKeeper) loop(ctx context.Context, firstIn time.Duration) {
	t := time.NewTimer(firstIn)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, _ := this.checkedRun(ctx)
			t.Reset(n)
		}
	}
}

func (this *houseKeeper) checkedRun(ctx context.Context) (nextRunIn time.Duration, rErr error) {
	l := this.logger()
	started := time.Now()
	defer func() {
		nextRunIn = this.service.Configuration.HouseKeeping.Every.Native()
		ld := l.
			With("duration", time.Since(started).Truncate(time.Microsecond)).
			With("nextRunIn", nextRunIn)
		if rErr != nil {
			ld.WithError(rErr).Error("housekeeping run failed")
		} else {
			ld.Info("housekeeping run done")
		}
	}()

	defer func() {
		if v := recover(); v != nil {
			if err, ok := v.(error); ok {
				rErr = err
			} else {
				rErr = fmt.Errorf("panic while housekeeping occurred: %v", v)
			}
		}
	}()

	l.Debug("housekeeping run started")

	return 0, this.run(l, ctx)
}

func (this *houseKeeper) run(logger log.Logger, ctx context.Context) error {
	if err := this.inspectSessions(logger, ctx); err != nil {
		return err
	}
	if err := this.cleanup(logger, ctx); err != nil {
		return err
	}
	return nil
}

func (this *houseKeeper) inspectSessions(logger log.Logger, ctx context.Context) error {
	return this.service.sessions.FindAll(ctx, this.inspectSession, &session.FindOpts{
		AutoCleanUpAllowed: common.P(this.service.Configuration.HouseKeeping.AutoRepair),
		Logger:             logger,
	})
}

func (this *houseKeeper) inspectSession(ctx context.Context, sess session.Session) (bool, error) {
	logger := this.logger().With("session", sess)
	started := time.Now()

	reportAndContiue := func(err error) (bool, error) {
		logger.WithError(err).
			With("duration", time.Since(started).Truncate(time.Microsecond)).
			Warn("cannot inspect session; skipping...")
		return true, nil
	}

	logger.Debug("inspecting session...")

	if shouldBeDeleted, err := session.IsExpiredWithThreshold(this.service.Configuration.HouseKeeping.KeepExpiredFor.Native())(ctx, sess); err != nil {
		return reportAndContiue(err)
	} else if shouldBeDeleted {
		if _, err := this.dispose(ctx, logger, sess); err != nil {
			return reportAndContiue(err)
		}

		if err := this.service.sessions.Delete(ctx, sess); err != nil {
			return reportAndContiue(err)
		}
		logger.Info("session reached maximum age to be kept after being expired and was therefore deleted")

	} else if expired, err := session.IsExpired(ctx, sess); err != nil {
		return reportAndContiue(err)
	} else if expired {
		disposed, err := this.dispose(ctx, logger, sess)
		if err != nil {
			return reportAndContiue(err)
		}
		if disposed {
			logger.Info("session is expired and was therefore disposed")
		} else {
			logger.Trace("session is expired and was therefore disposed; but nothing relevant happen while disposing all components")
		}
	}

	if logger.IsDebugEnabled() {
		logger.
			With("duration", time.Since(started).Truncate(time.Microsecond)).
			Debug("inspecting session... DONE!")
	}

	return true, nil
}

// dispose will dispose a given session.Session but NOT delete it.
func (this *houseKeeper) dispose(ctx context.Context, logger log.Logger, sess session.Session) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose session %v: %w", sess, err)
	}

	environmentDisposed, err := this.disposeEnvironment(ctx, logger, sess)
	if err != nil {
		return fail(err)
	}
	authorizationDisposed, err := this.disposeAuthorization(ctx, logger, sess)
	if err != nil {
		return fail(err)
	}
	sessionDisposed, err := sess.Dispose(ctx)
	if err != nil {
		return fail(err)
	}

	return environmentDisposed || authorizationDisposed || sessionDisposed, nil
}

func (this *houseKeeper) disposeEnvironment(ctx context.Context, logger log.Logger, sess session.Session) (_ bool, rErr error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose authorization: %w", err)
	}

	env, err := this.service.environments.FindBySession(ctx, sess, &environment.FindOpts{
		AutoCleanUpAllowed: common.P(true),
		Logger:             logger,
	})
	if errors.Is(err, environment.ErrNoSuchEnvironment) {
		// Ok, treat it as already disposed.
		return false, nil
	}
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, env)

	disposed, err := env.Dispose(ctx)
	if err != nil {
		return fail(err)
	}

	return disposed, nil
}
func (this *houseKeeper) disposeAuthorization(ctx context.Context, logger log.Logger, sess session.Session) (bool, error) {
	reportOnly := func(err error) (bool, error) {
		logger.WithError(err).
			Warn("cannot dispose authorization of session; skipping...")
		return false, nil
	}

	auth, err := this.service.authorizer.RestoreFromSession(ctx, sess, &authorization.RestoreOpts{
		AutoCleanUpAllowed: common.P(true),
		Logger:             logger,
	})
	if errors.Is(err, authorization.ErrNoSuchAuthorization) {
		// Ok, treat it as already disposed.
		return false, nil
	}
	if err != nil {
		return reportOnly(err)
	}

	disposed, err := auth.Dispose(ctx)
	if err != nil {
		return reportOnly(err)
	}

	return disposed, nil
}

func (this *houseKeeper) cleanup(logger log.Logger, ctx context.Context) error {
	return this.service.environments.Cleanup(ctx, &environment.CleanupOpts{
		FlowOfNamePredicate: this.doesFlowExists,
		Logger:              logger,
	})
}

func (this *houseKeeper) doesFlowExists(name configuration.FlowName) (bool, error) {
	_, ok := this.service.knownFlows[name]
	return ok, nil
}

func (this *houseKeeper) Close() error {
	if !this.closed.CompareAndSwap(false, true) {
		return nil
	}
	this.contextCancel()
	return nil
}

func (this *houseKeeper) logger() log.Logger {
	if v := this.service.Logger; v != nil {
		return v
	}
	return log.GetLogger("housekeeping")
}
