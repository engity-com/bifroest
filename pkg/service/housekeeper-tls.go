package service

import (
	"context"
	"errors"
	"fmt"
)

type housekeepingTLSRuntime struct{ context.Context }

// The initial housekeeping pass precedes listener startup. Renewal may begin
// only after TLS preparation; stopping the listeners also cancels active orders.
func (this *houseKeeper) startTLSRenewal(ctx context.Context) {
	this.tlsRuntime.Store(&housekeepingTLSRuntime{ctx})
}

func (this *houseKeeper) renewTLS(ctx context.Context) error {
	runtime := this.tlsRuntime.Load()
	if runtime == nil || runtime.Err() != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(runtime.Context, cancel)
	defer stop()
	defer cancel()
	var result error
	for _, name := range this.service.tlsSourceNames {
		if runtime.Err() != nil {
			return result
		}
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		manager := this.service.tlsManagers[name]
		if manager == nil {
			continue
		}
		if err := manager.RenewDue(ctx); err != nil {
			if runtime.Err() != nil {
				return result
			}
			if ctx.Err() != nil {
				return errors.Join(result, ctx.Err())
			}
			this.service.tlsRefreshFailed(name, "renewal", err)
			result = errors.Join(result, fmt.Errorf("TLS source %q renewal: %w", name, err))
		}
	}
	return result
}
