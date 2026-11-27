package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type runtimeRestartRequiredError struct{ sections []string }

func (this *runtimeRestartRequiredError) Error() string {
	return "configuration reload requires restart: " + strings.Join(this.sections, ", ")
}

type runtimeReloadFailure struct {
	reason string
	cause  error
}

func (this *runtimeReloadFailure) Error() string { return this.cause.Error() }
func (this *runtimeReloadFailure) Unwrap() error { return this.cause }

func (this *service) applyConfigurationReload(ctx context.Context, snapshot *configuration.Snapshot, _ configuration.ReloadChanges) (resultErr error) {
	candidate, err := this.prepareGeneration(ctx, snapshot.Configuration())
	if err != nil {
		reason := "preparation_failed"
		var restart *runtimeRestartRequiredError
		switch {
		case errors.As(err, &restart):
			reason = "restart_required"
		case errors.Is(err, common.ErrProviderBootstrapDisabled):
			reason = "provisioning_required"
		}
		return &runtimeReloadFailure{reason, err}
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, candidate.Close())
		}
	}()
	_, err = this.activateGeneration(ctx, candidate)
	if err != nil {
		return &runtimeReloadFailure{"activation_failed", err}
	}
	committed = true
	// Publication has committed. Fallible cleanup is logged by activation and
	// must never reject the source snapshot; it needs a later retry.
	return nil
}

func (this *service) configurationReloadError(err error) {
	if errors.Is(err, context.Canceled) && !errors.Is(err, errUncertainRuntimeCommit) {
		return
	}
	var watch *configuration.FileWatchError
	if errors.As(err, &watch) {
		if this.monitoring != nil {
			this.monitoring.reload.watchErrors.Inc()
		}
		this.logger().Warn("configuration watch degraded; polling remains active")
		return
	}
	reason := "invalid_configuration"
	var failure *runtimeReloadFailure
	if errors.As(err, &failure) {
		reason = failure.reason
	}
	if this.monitoring != nil {
		this.monitoring.observeReload("rejected")
	}
	if errors.Is(err, errUncertainRuntimeCommit) {
		this.logger().With("reason", "persistence_uncertain").Error("configuration authority is uncertain; admission stopped")
		return
	}
	var restart *runtimeRestartRequiredError
	if errors.As(err, &restart) {
		this.logger().With("reason", reason).With("sections", strings.Join(restart.sections, ", ")).
			Warn("configuration reload rejected; restart required for changed sections")
		return
	}
	// YAML, templates and dependency errors can contain credentials. Only
	// server-controlled categories are logged here, never the raw error.
	this.logger().With("reason", reason).Warn("configuration reload rejected; last accepted configuration retained")
}

func (this *service) configurationReloaded(changes configuration.ReloadChanges) {
	result := "unchanged"
	if changes.Changed {
		result = "accepted"
	}
	if this.monitoring != nil {
		this.monitoring.observeReload(result)
	}
	if changes.Changed {
		this.logger().With("runtimeChanged", changes.RuntimeChanged()).
			With("addedFlows", len(changes.AddedFlows)).With("removedFlows", len(changes.RemovedFlows)).
			With("modifiedFlows", len(changes.ModifiedFlows)).Info("configuration source accepted")
	}
}

// Install the native watcher before publishing startup readiness. The watcher
// cannot attempt activation until listeners have published their ready state.
// It is a listener-owned worker and joins shutdown before repositories close.
func (this *service) prepareConfigurationWatch(inputs *runtimeListeners) (func(), error) {
	if this.configurationReloader == nil {
		return func() {}, nil
	}
	ready, resume := make(chan struct{}), make(chan struct{})
	options := this.configurationWatchOptions
	options.OnReady = func() {
		close(ready)
		select {
		case <-resume:
		case <-inputs.ctx.Done():
		}
	}
	options.OnError, options.OnReload = this.configurationReloadError, this.configurationReloaded
	inputs.start(boundInput{}, "configuration watch", func() error {
		return this.configurationReloader.Watch(inputs.ctx, options)
	})
	for {
		select {
		case <-ready:
			return func() { close(resume) }, nil
		case <-inputs.ctx.Done():
			return nil, inputs.ctx.Err()
		case <-inputs.wake:
			inputs.mutex.Lock()
			failure := inputs.failure
			inputs.mutex.Unlock()
			if failure != nil {
				return nil, fmt.Errorf("cannot start configuration watch: %w", failure)
			}
		}
	}
}
