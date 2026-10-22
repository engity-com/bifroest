package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/https"
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
	if bind == nil {
		bind = func(address bnet.Address) (net.Listener, error) { return address.Listen() }
	}
	var inputs []boundInput
	closeInputs := func() {
		for _, input := range inputs {
			if err := input.listener.Close(); this.isProblematicError(err) {
				rErr = errors.Join(rErr, fmt.Errorf("cannot close %s listener: %w", input.transport, err))
			}
		}
	}
	defer closeInputs()
	groups := []struct {
		addresses bnet.NetAddresses
		transport string
	}{{this.Configuration.Ssh.Addresses, "SSH"}}
	if this.https != nil {
		groups = append(groups, struct {
			addresses bnet.NetAddresses
			transport string
		}{this.Configuration.Http.Addresses, "HTTPS"})
	}
	for _, group := range groups {
		for _, address := range group.addresses {
			if err := parent.Err(); err != nil {
				return shutdown, err
			}
			listener, err := bind(address)
			if err != nil {
				return shutdown, fmt.Errorf("cannot bind %s listener %v: %w", group.transport, address, err)
			}
			inputs = append(inputs, boundInput{listener, address, group.transport})
		}
	}
	if len(inputs) == 0 {
		return shutdown, fmt.Errorf("no incoming listeners configured")
	}
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	// Every task has exactly one buffered result, including aborted preparation.
	results := make(chan inputResult, len(inputs)+2)
	running := 0
	start := func(input boundInput, operation string, serve func() error) {
		running++
		go func() {
			if operation != "listener" {
				results <- inputResult{input, operation, serve()}
				return
			}
			logger := this.logger().With("address", input.listener.Addr()).With("transport", input.transport)
			logger.Info("listening...")
			err := serve()
			if this.isProblematicError(err) && !errors.Is(err, http.ErrServerClosed) {
				logger.WithError(err).Error("listening... FAILED!")
			} else {
				logger.Info("listening... DONE!")
			}
			results <- inputResult{input, operation, err}
		}()
	}
	for _, input := range inputs {
		if input.transport == "HTTPS" {
			start(input, "listener", func() error { return this.https.Serve(input.listener) })
		}
	}
	prepared := this.https == nil
	if !prepared {
		start(boundInput{}, "HTTPS preparation", func() error { return this.https.Prepare(ctx) })
	}
	failed := false
	for !prepared && !failed {
		select {
		case <-ctx.Done():
			shutdown.cause = context.Cause(ctx)
			failed = true
		case result := <-results:
			running--
			if ctx.Err() != nil {
				shutdown.cause = context.Cause(ctx)
				failed = true
			} else if result.operation == "HTTPS preparation" && result.err == nil {
				prepared = true
			} else {
				rErr = inputFailure(result)
				shutdown.cause = rErr
				failed = true
			}
		}
	}
	if !failed && ctx.Err() == nil {
		for _, input := range inputs {
			if input.transport == "SSH" {
				start(input, "listener", func() error { return this.server.Serve(ctx, input.listener) })
			}
		}
		if this.https != nil {
			start(boundInput{}, "HTTPS renewal", func() error {
				return this.https.RunRenewal(ctx, func(err error) {
					this.logger().WithError(err).Warn("HTTPS certificate renewal failed; existing valid material retained")
				})
			})
		}
		this.logger().WithAll(sys.VersionToMap(this.Version)).Info("started")
		select {
		case <-ctx.Done():
			shutdown.cause = context.Cause(ctx)
		case result := <-results:
			running--
			if ctx.Err() != nil {
				shutdown.cause = context.Cause(ctx)
			} else {
				rErr = inputFailure(result)
				shutdown.cause = rErr
			}
			shutdown.forced = errors.Is(result.err, essh.ErrGracefulShutdownTimeout)
		}
	}
	if shutdown.cause == nil {
		shutdown.cause = context.Cause(ctx)
	}
	shutdown.startedAt = time.Now()
	this.connectionLifecycle.stop()
	if this.terminalAdmissions != nil {
		this.terminalAdmissions.stop()
	}
	if this.cancelTerminals != nil {
		this.cancelTerminals()
	}
	if this.executions != nil {
		this.executions.stop()
	}
	cancel(shutdown.cause)
	rErr = errors.Join(rErr, this.sessionConnections.closeTerminals())
	// Stop all accepting immediately; HTTP grace and SSH grace run concurrently.
	// Close only raw listeners here; the servers own active connections.
	closeInputs()
	if this.https != nil {
		rErr = errors.Join(rErr, this.https.Close())
	}
	for running > 0 {
		result := <-results
		running--
		shutdown.forced = shutdown.forced || errors.Is(result.err, essh.ErrGracefulShutdownTimeout)
		if this.isProblematicError(result.err) && !errors.Is(result.err, http.ErrServerClosed) && !errors.Is(result.err, https.ErrClosed) {
			rErr = errors.Join(rErr, inputFailure(result))
		}
	}
	if rErr == nil && this.isProblematicError(shutdown.cause) {
		rErr = shutdown.cause
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
