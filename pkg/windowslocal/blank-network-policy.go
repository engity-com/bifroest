package windowslocal

import (
	"context"
	"errors"
	"fmt"
)

const samBlankPolicyDWORD uint32 = 4

type samBlankNetworkPolicyOperations struct {
	open  func() (uintptr, error)
	read  func(uintptr) (uint64, uint32, error)
	close func(uintptr) error
}

// This is a fresh native restriction, not account eligibility. Unknown or absent
// policy is never replaced by an assumed Windows default. Cleanup failure or
// cancellation must not produce an apparently unrestricted result with nil error.
func inspectSAMBlankNetworkPolicyFlow(ctx context.Context, api samBlankNetworkPolicyOperations) (restricted bool, resultErr error) {
	if ctx == nil {
		return false, fmt.Errorf("missing SAM blank-network-policy context")
	}
	defer func() {
		resultErr = errors.Join(resultErr, ctx.Err())
		if resultErr != nil {
			restricted = false
		}
	}()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if api.open == nil || api.read == nil || api.close == nil {
		return false, fmt.Errorf("incomplete SAM blank-network-policy operations")
	}
	key, err := api.open()
	if key != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.close(key)) }()
	}
	if err != nil {
		return false, err
	}
	if key == 0 {
		return false, fmt.Errorf("registry open returned no blank-network-policy key")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	value, kind, err := api.read(key)
	if err != nil {
		return false, err
	}
	if kind != samBlankPolicyDWORD || value > 1 {
		return false, fmt.Errorf("unknown native blank-network-policy type or value")
	}
	return value == 1, nil
}
