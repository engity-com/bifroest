package management

import "errors"

// Flush while the terminal still has secret input/echo disabled. Restore and
// release remain mandatory even if flushing fails; callers retain the original
// challenge error alongside these cleanup errors before releasing their gate.
func closeConsoleInputLifecycle(discard bool, flush, restore, release func() error) error {
	var flushErr error
	if discard {
		flushErr = flush()
	}
	return errors.Join(flushErr, restore(), release())
}
