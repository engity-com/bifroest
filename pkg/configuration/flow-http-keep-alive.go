package configuration

import (
	"fmt"
	"time"
)

const (
	DefaultHttpKeepAlive = 15 * time.Second
	MinimumHttpKeepAlive = time.Second
	MaximumHttpKeepAlive = 5 * time.Minute
)

type HttpKeepAlive struct {
	Interval time.Duration
	Locked   bool
}

// Only the server renders the policy, using the authenticated session context.
// Never include rendered template values or causes in parse errors.
func (this FlowHttp) ResolveKeepAlive(context any) (HttpKeepAlive, error) {
	if this.KeepAlive.IsZero() {
		return HttpKeepAlive{Interval: DefaultHttpKeepAlive}, nil
	}
	interval, locked, err := this.KeepAlive.RenderBounded(context, 64)
	if err != nil {
		return HttpKeepAlive{}, fmt.Errorf("keepAlive template evaluation failed")
	}
	if err := validateHttpKeepAliveInterval(interval); err != nil {
		return HttpKeepAlive{}, err
	}
	return HttpKeepAlive{Interval: interval, Locked: locked}, nil
}

func ParseHttpKeepAlive(value string) (time.Duration, error) {
	if len(value) == 0 || len(value) > 64 {
		return 0, fmt.Errorf("invalid keepAlive duration")
	}
	interval, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid keepAlive duration")
	}
	if err := validateHttpKeepAliveInterval(interval); err != nil {
		return 0, err
	}
	return interval, nil
}

func validateHttpKeepAliveInterval(interval time.Duration) error {
	if interval < MinimumHttpKeepAlive || interval > MaximumHttpKeepAlive {
		return fmt.Errorf("keepAlive must be between 1s and 5m")
	}
	return nil
}
