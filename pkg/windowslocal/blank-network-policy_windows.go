//go:build windows

package windowslocal

import (
	"context"

	"golang.org/x/sys/windows/registry"
)

func inspectSAMBlankNetworkPolicy(ctx context.Context) (bool, error) {
	return inspectSAMBlankNetworkPolicyFlow(ctx, samBlankNetworkPolicyOperations{
		open: func() (uintptr, error) {
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
			return uintptr(key), err
		},
		read: func(key uintptr) (uint64, uint32, error) {
			return registry.Key(key).GetIntegerValue("LimitBlankPasswordUse")
		},
		close: func(key uintptr) error { return registry.Key(key).Close() },
	})
}
