package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

type listenerShutdown struct {
	startedAt time.Time
	forced    bool
	cause     error
}
type boundInput struct {
	listener  net.Listener
	address   bnet.Address
	transport string
}
type inputResult struct {
	input     boundInput
	operation string
	err       error
}

func (this *service) runListeners(parent context.Context, bind func(bnet.Address) (net.Listener, error)) (shutdown listenerShutdown, rErr error) {
	inputs := newRuntimeListeners(this, parent, bind)
	defer close(inputs.done)
	defer inputs.cancel(nil)
	defer func() { rErr = errors.Join(rErr, inputs.stop()) }()
	plan, err := inputs.prepare(parent, this.Configuration)
	if err != nil {
		return shutdown, err
	}
	defer func() { rErr = errors.Join(rErr, plan.close()) }()
	if len(plan.specs) == 0 && this.sshTunnel == nil {
		return shutdown, fmt.Errorf("no incoming listeners configured")
	}
	inputs.mutex.Lock()
	inputs.installLocked(plan)
	inputs.mutex.Unlock()
	this.resources.mutex.Lock()
	if this.resources.listeners != nil || this.resources.ctx.Err() != nil {
		this.resources.mutex.Unlock()
		return shutdown, fmt.Errorf("runtime listeners already started or stopping")
	}
	this.resources.listeners = inputs
	this.resources.mutex.Unlock()
	inputs.startScopes("HTTPS")
	inputs.startScopes("TLS challenge")
	if this.monitoring != nil {
		inputs.start(boundInput{}, "journal space observation", func() error { return this.monitoring.runJournalObserver(inputs.ctx, this) })
	}
	if !inputs.prepared {
		inputs.start(boundInput{}, "HTTPS preparation", func() error { return this.prepareTLSBindings(inputs.ctx) })
	}
	for {
		inputs.mutex.Lock()
		prepared, failure := inputs.prepared, inputs.failure
		inputs.mutex.Unlock()
		if prepared || failure != nil || inputs.ctx.Err() != nil {
			break
		}
		select {
		case <-inputs.ctx.Done():
		case <-inputs.wake:
		}
	}
	inputs.mutex.Lock()
	start := inputs.prepared && inputs.failure == nil && inputs.ctx.Err() == nil
	inputs.mutex.Unlock()
	startWatch := func() {}
	if start {
		startWatch, err = this.prepareConfigurationWatch(inputs)
		start = err == nil
	}
	if start {
		inputs.startScopes("SSH")
		if this.sshTunnel != nil {
			inputs.start(boundInput{listener: this.sshTunnel, transport: "SSH tunnel"}, "listener", func() error { return this.tunnelServer.Serve(inputs.ctx, this.sshTunnel) })
			this.sshTunnel.ready.Store(true)
		}
		this.houseKeeper.startTLSRenewal(inputs.ctx)
		for _, name := range this.tlsSourceNames {
			manager := this.tlsManagers[name]
			if manager.HasFileCertificates() {
				inputs.start(boundInput{}, "TLS file reload", func() error {
					return manager.RunFileReload(inputs.ctx, func(err error) {
						this.tlsRefreshFailed(name, "file reload", err)
					})
				})
			}
		}
		inputs.mutex.Lock()
		inputs.ready = true
		if this.monitoring != nil {
			this.monitoring.setReady(true)
		}
		inputs.mutex.Unlock()
		startWatch()
		this.logger().WithAll(sys.VersionToMap(this.Version)).Info("started")
		for inputs.ctx.Err() == nil {
			inputs.mutex.Lock()
			failure := inputs.failure
			inputs.mutex.Unlock()
			if failure != nil {
				break
			}
			select {
			case <-inputs.ctx.Done():
			case <-inputs.wake:
			}
		}
	}
	inputs.mutex.Lock()
	shutdown.cause = inputs.failure
	rErr = errors.Join(rErr, inputs.failure)
	inputs.ready = false
	inputs.mutex.Unlock()
	if shutdown.cause == nil {
		shutdown.cause = context.Cause(inputs.ctx)
	}
	shutdown.startedAt = time.Now()
	this.handlerLifecycle().stop()
	this.runtime.stop()
	if this.monitoring != nil {
		this.monitoring.setReady(false)
	}
	if this.web != nil {
		this.web.stop()
	}
	this.terminalAdmissions.stop()
	this.cancelTerminals()
	this.executions.stop()
	inputs.cancel(shutdown.cause)
	rErr = errors.Join(rErr, this.sessionConnections.closeTerminals(), inputs.stop())
	inputs.workers.Wait()
	inputs.mutex.Lock()
	shutdown.forced = inputs.forced
	rErr = errors.Join(rErr, inputs.closeErr)
	inputs.mutex.Unlock()
	if this.sshTunnel != nil {
		this.sshTunnel.operations.waitUntilDrained()
	}
	if this.https != nil {
		rErr = errors.Join(rErr, this.https.Close())
	}
	rErr = errors.Join(rErr, this.closeTLS())
	if rErr == nil && this.isProblematicError(shutdown.cause) {
		rErr = errors.Join(rErr, shutdown.cause)
	}
	return shutdown, rErr
}

func inputFailure(result inputResult) error {
	if result.operation == "listener" {
		if result.err != nil {
			return fmt.Errorf("%s listener %v failed: %w", result.input.transport, result.input.address, result.err)
		}
		return fmt.Errorf("%s listener %v stopped unexpectedly", result.input.transport, result.input.address)
	}
	if result.err != nil {
		return fmt.Errorf("%s failed: %w", result.operation, result.err)
	}
	return fmt.Errorf("%s stopped unexpectedly", result.operation)
}
