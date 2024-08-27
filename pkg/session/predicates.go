package session

import (
	"context"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
)

type Predicate func(context.Context, Session) (bool, error)

func IsNotExpired(ctx context.Context, candidate Session) (bool, error) {
	expired, err := IsExpired(ctx, candidate)
	return !expired && err == nil, err
}

func IsExpired(ctx context.Context, candidate Session) (bool, error) {
	return isExpiredWithThreshold(ctx, candidate, 0)
}

func IsExpiredWithThreshold(threshold time.Duration) Predicate {
	return func(ctx context.Context, candidate Session) (bool, error) {
		return isExpiredWithThreshold(ctx, candidate, threshold)
	}
}

func isExpiredWithThreshold(ctx context.Context, candidate Session, threshold time.Duration) (bool, error) {
	info, err := candidate.Info(ctx)
	if err != nil {
		return false, err
	}
	if info.State() == StateDisposed {
		return true, nil
	}
	vu, err := info.ValidUntil(ctx)
	if err != nil {
		return false, err
	}
	if vu.IsZero() {
		return false, nil
	}
	return !time.Now().Before(vu.Add(threshold)), nil
}

func IsStillValid(ctx context.Context, candidate Session) (bool, error) {
	if ok, err := IsNotExpired(ctx, candidate); err != nil || !ok {
		return false, err
	}
	return true, nil
}

func IsFlow(flow configuration.FlowName) Predicate {
	return func(ctx context.Context, candidate Session) (bool, error) {
		return candidate != nil && candidate.Flow().IsEqualTo(flow), nil
	}
}

func IsRemoteName(name string) Predicate {
	return func(ctx context.Context, candidate Session) (bool, error) {
		if candidate == nil {
			return false, nil
		}
		si, err := candidate.Info(ctx)
		if err != nil {
			return false, err
		}
		created, err := si.Created(ctx)
		if err != nil {
			return false, err
		}
		return created != nil && created.Remote().User() == name, nil
	}
}

type Predicates []Predicate

func (this Predicates) Matches(ctx context.Context, candidate Session) (bool, error) {
	for _, predicate := range this {
		if ok, err := predicate(ctx, candidate); err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}
