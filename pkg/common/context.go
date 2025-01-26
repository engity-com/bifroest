package common

import (
	"context"
	"time"
)

func Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func SleepSilently(ctx context.Context, duration time.Duration) {
	_ = Sleep(ctx, duration)
}
