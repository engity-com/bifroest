// Package client consumes typed management responses without SSH, CLI, filesystem
// or authentication dependencies. It does not open connections or interpret
// commands. Transports must separately enforce their typed request and authority.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Response transfers ownership of one already-started operation to Receive.
// Complete is called exactly once, after decoding (or Abort). It must join the
// producer/diagnostics and report the operation's final success, not merely EOF.
// Abort must be safe alongside Read/Complete and unblock both; it must NOT wait
// for Receive or Complete. Close releases local resources without waiting for a
// peer, after the cancellation callback has been joined. None of these methods
// retry, undo or reopen an operation. Caller decoders/sinks must also cooperate
// with cancellation; this API cannot interrupt an arbitrary blocked local writer.
type Response interface {
	io.Reader
	Complete() error
	Abort() error
	Close() error
}

// Receive owns the response through decode, final transport completion and local
// cleanup. Any error, including late cancellation or Close failure, returns the
// zero T. Decoder callbacks/writes remain provisional; only the caller can stage
// or publish them. Success is NOT evidence signature/trust/decryption verification.
// A nil context uses Background. Cancellation callbacks never outlive this call.
func Receive[T any](ctx context.Context, response Response, decode func(io.Reader) (T, error)) (result T, resultErr error) {
	if response == nil {
		return result, fmt.Errorf("missing management response")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var abortOnce sync.Once
	var abortErr error
	abort := func() { abortOnce.Do(func() { abortErr = response.Abort() }) }
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(cancelDone); abort() })
	completionStarted, completed := false, false
	defer func() {
		// Also release ownership if a caller decoder panics. Do not retry a
		// Complete that itself panicked; adapter panics still propagate.
		if !completed {
			abort()
			if !completionStarted {
				completionStarted = true
				resultErr = errors.Join(resultErr, response.Complete())
			}
		}
		if !stop() {
			<-cancelDone
		}
		closeErr := response.Close()
		resultErr = errors.Join(resultErr, ctx.Err(), abortErr, closeErr)
		if resultErr != nil {
			var zero T
			result = zero
		}
	}()
	if ctx.Err() != nil {
		resultErr = ctx.Err()
	} else if decode == nil {
		resultErr = fmt.Errorf("missing management decoder")
	} else {
		result, resultErr = decode(response)
	}
	if resultErr != nil || ctx.Err() != nil {
		abort()
	}
	completionStarted = true
	completeErr := response.Complete()
	completed = true
	if completeErr != nil {
		abort()
	}
	resultErr = errors.Join(resultErr, completeErr)
	return result, resultErr
}
