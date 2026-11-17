package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"runtime"
)

var errS4USystemContext = errors.New("local S4U requires an unimpersonated LocalSystem context")
var errS4UNativeWorker = errors.New("local S4U native worker did not complete normally")

type s4uSystemContextOperations struct {
	processSystem func() (bool, error)
	threadToken   func() (uintptr, error) // Zero/nil means explicit native ERROR_NO_TOKEN, never a NULL-success guess.
	closeToken    func(uintptr) error
}

func inspectS4USystemContextFlow(ctx context.Context, api s4uSystemContextOperations) (resultErr error) {
	if ctx == nil {
		return fmt.Errorf("missing local S4U system context")
	}
	defer func() { resultErr = errors.Join(resultErr, ctx.Err()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if api.processSystem == nil || api.threadToken == nil || api.closeToken == nil {
		return fmt.Errorf("incomplete local S4U identity operations")
	}
	system, err := api.processSystem()
	if err != nil {
		return err
	}
	if !system {
		return errS4USystemContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := api.threadToken()
	if token != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.closeToken(token)) }()
	}
	if token != 0 {
		return errors.Join(errS4USystemContext, err)
	}
	return err
}

// The caller remains pinned from its initial check through the worker join and
// its final check, so the worker cannot borrow the caller's thread. Native work
// is joined on a separate pinned thread. That worker intentionally never
// unlocks: Go retires the OS thread when its goroutine exits, so an unexpected
// native identity change cannot return that thread to the scheduler's pool.
// Cancellation never abandons native work or its cleanup. Callback completion
// is joined; physical OS-thread termination follows goroutine exit separately.
func runS4USystemContext(ctx context.Context, inspect func() error, action func() error) error {
	return runS4USystemContextOnThread(ctx, inspect, action, s4uOnStartupThread)
}

func runS4USystemContextOnThread(ctx context.Context, inspect func() error, action func() error, onStartupThread func() (bool, error)) error {
	if ctx == nil {
		return fmt.Errorf("missing local S4U system context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if inspect == nil || action == nil || onStartupThread == nil {
		return fmt.Errorf("incomplete local S4U system-context operations")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.Join(inspect(), ctx.Err())
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	checkCaller := func() (result error) {
		completed := false
		defer func() {
			if recover() != nil || !completed {
				result = errS4UNativeWorker
			}
		}()
		result = check()
		completed = true
		return result
	}
	if callerErr := checkCaller(); callerErr != nil {
		return errors.Join(callerErr, ctx.Err())
	}
	done := make(chan error, 1)
	var startWorker func(chan<- error, bool)
	startWorker = func(output chan<- error, mayReserve bool) {
		go func() {
			runtime.LockOSThread()
			var result error
			completed := false
			reservationOnly := true
			defer func() {
				if recover() != nil || !completed {
					result = errS4UNativeWorker
				}
				if reservationOnly {
					runtime.UnlockOSThread()
				}
				output <- errors.Join(result, ctx.Err())
			}()
			startup, err := onStartupThread()
			if err != nil {
				result = err
				completed = true
				return
			}
			if startup {
				// Go parks m0 instead of physically terminating it. Hold it only
				// for this handoff; no native inspector/action may execute here.
				if !mayReserve {
					result = errS4UNativeWorker
					completed = true
					return
				}
				if err := ctx.Err(); err != nil {
					result = err
					completed = true
					return
				}
				child := make(chan error, 1)
				startWorker(child, false)
				result = <-child
				completed = true
				return
			}
			reservationOnly = false
			result = func() error {
				if err := check(); err != nil {
					return err
				}
				if err := action(); err != nil {
					return errors.Join(err, ctx.Err())
				}
				return check()
			}()
			completed = true
		}()
	}
	startWorker(done, true)
	if err := <-done; err != nil {
		return err
	}
	return errors.Join(checkCaller(), ctx.Err())
}
