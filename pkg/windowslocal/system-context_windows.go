//go:build windows

package windowslocal

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

var s4uStartupThreadID uint32

func init() {
	// Go documents that package initialization runs on the startup thread.
	// Record its identity without pinning main or altering any native token.
	s4uStartupThreadID = windows.GetCurrentThreadId()
}

func s4uOnStartupThread() (bool, error) {
	if s4uStartupThreadID == 0 {
		return false, fmt.Errorf("native startup thread identity unavailable")
	}
	return windows.GetCurrentThreadId() == s4uStartupThreadID, nil
}

// No impersonation, RevertToSelf or privilege adjustment is performed. The
// opened thread token is merely queried/closed; any present token is denied,
// including an impersonation token whose user SID is also LocalSystem.
func inspectS4USystemContext(ctx context.Context) error {
	return inspectS4USystemContextFlow(ctx, s4uSystemContextOperations{
		processSystem: func() (bool, error) {
			system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
			if err != nil {
				return false, fmt.Errorf("resolve LocalSystem SID: %w", err)
			}
			if err := ctx.Err(); err != nil {
				return false, err
			}
			self, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil {
				return false, fmt.Errorf("read native process identity: %w", err)
			}
			return self != nil && self.User.Sid != nil && self.User.Sid.IsValid() && self.User.Sid.Equals(system), nil
		},
		threadToken: func() (uintptr, error) {
			var token windows.Token
			err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
			if errors.Is(err, windows.ERROR_NO_TOKEN) && token == 0 {
				return 0, nil
			}
			if err != nil {
				return uintptr(token), fmt.Errorf("read native thread identity: %w", err)
			}
			if token == 0 {
				return 0, fmt.Errorf("OpenThreadToken returned no token without ERROR_NO_TOKEN")
			}
			return uintptr(token), nil
		},
		closeToken: func(token uintptr) error { return windows.Token(token).Close() },
	})
}

func withS4USystemContext(ctx context.Context, action func() error) error {
	return runS4USystemContext(ctx, func() error { return inspectS4USystemContext(ctx) }, action)
}
