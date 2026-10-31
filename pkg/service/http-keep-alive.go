package service

import (
	"fmt"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
)

type webKeepAlive struct {
	Interval string `json:"interval"`
	Locked   bool   `json:"locked"`
}

func (this *webService) keepAlivePolicy(base *environmentContext) (configuration.HttpKeepAlive, error) {
	if base.Authorization() == nil || !base.Authorization().IsAuthorized() || base.Authorization().FindSession() == nil {
		return configuration.HttpKeepAlive{}, errWebAccessDenied
	}
	for _, flow := range this.service.Configuration.Flows {
		if flow.Name == base.Authorization().Flow() && flow.Http.IsEnabled() {
			return flow.Http.ResolveKeepAlive(base)
		}
	}
	return configuration.HttpKeepAlive{}, errWebAccessDenied
}

func webKeepAliveView(policy configuration.HttpKeepAlive) webKeepAlive {
	return webKeepAlive{Interval: policy.Interval.String(), Locked: policy.Locked}
}

func (this *webService) configureKeepAlive(base *environmentContext, stream *webTerminalStream, requested string) (webKeepAlive, error) {
	policy, err := this.keepAlivePolicy(base)
	if err != nil {
		return webKeepAlive{}, fmt.Errorf("connection keepAlive policy unavailable")
	}
	interval := policy.Interval
	if requested != "" && !policy.Locked {
		interval, err = configuration.ParseHttpKeepAlive(requested)
		if err != nil {
			return webKeepAlive{}, fmt.Errorf("invalid connection keepAlive")
		}
	}
	// Preserve accelerated internal transport timings in lifecycle fixtures when
	// no configuration/preference overrides the ordinary default.
	if interval != configuration.DefaultHttpKeepAlive || requested != "" {
		if err := stream.setKeepAliveInterval(interval, max(45*time.Second, 3*interval)); err != nil {
			return webKeepAlive{}, fmt.Errorf("connection keepAlive unavailable")
		}
	}
	return webKeepAlive{Interval: interval.String(), Locked: policy.Locked}, nil
}
