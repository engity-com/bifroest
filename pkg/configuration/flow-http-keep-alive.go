package configuration

import (
	"fmt"
	"strings"
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
	value, err := this.KeepAlive.Render(context)
	if err != nil {
		return HttpKeepAlive{}, fmt.Errorf("keepAlive template evaluation failed")
	}
	value = strings.TrimSpace(value)
	locked := strings.HasPrefix(value, "!")
	if locked {
		value = value[1:]
	}
	interval, err := ParseHttpKeepAlive(value)
	return HttpKeepAlive{Interval: interval, Locked: locked}, err
}

func ParseHttpKeepAlive(value string) (time.Duration, error) {
	if len(value) == 0 || len(value) > 64 {
		return 0, fmt.Errorf("invalid keepAlive duration")
	}
	interval, err := time.ParseDuration(value)
	if err != nil || interval < MinimumHttpKeepAlive || interval > MaximumHttpKeepAlive {
		return 0, fmt.Errorf("keepAlive must be a Go duration between 1s and 5m")
	}
	return interval, nil
}
