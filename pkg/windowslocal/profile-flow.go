package windowslocal

import (
	"context"
	"errors"
	"fmt"
)

type samProfileOperations struct {
	identity      func() error
	system        func() error
	s4u           func() (uintptr, error)
	duplicate     func(uintptr) (uintptr, error)
	tokenIdentity func(uintptr) error
	load          func(uintptr) (uintptr, error)
	directory     func(uintptr) (string, error)
	unload        func(uintptr, uintptr) error
	closeToken    func(uintptr) error
}

// A fresh native profile path is not a persisted environment snapshot. Cleanup
// remains synchronous; API/cleanup/context failure must never return a path.
func readSAMProfileDirectory(ctx context.Context, api samProfileOperations) (home string, resultErr error) {
	if ctx == nil {
		return "", fmt.Errorf("missing native profile context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if api.identity == nil || api.system == nil || api.s4u == nil || api.duplicate == nil || api.tokenIdentity == nil || api.load == nil || api.directory == nil || api.unload == nil || api.closeToken == nil {
		return "", fmt.Errorf("incomplete native profile operations")
	}
	step := func(action func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.Join(action(), ctx.Err())
	}
	defer func() {
		if resultErr == nil && ctx.Err() == nil && home != "" {
			resultErr = step(api.identity)
			if resultErr == nil {
				resultErr = step(api.system)
			}
		}
		resultErr = errors.Join(resultErr, ctx.Err())
		if resultErr != nil {
			home = ""
		}
	}()
	if err := step(api.identity); err != nil {
		return "", err
	}
	if err := step(api.system); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	impersonation, err := api.s4u()
	if impersonation != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.closeToken(impersonation)) }()
	}
	if err != nil {
		return "", err
	}
	if impersonation == 0 {
		return "", fmt.Errorf("profile S4U returned no token")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	primary, err := api.duplicate(impersonation)
	if primary != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.closeToken(primary)) }()
	}
	if err != nil {
		return "", err
	}
	if primary == 0 {
		return "", fmt.Errorf("DuplicateTokenEx returned no token")
	}
	if err := step(func() error { return api.tokenIdentity(primary) }); err != nil {
		return "", err
	}
	if err := step(api.identity); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	profile, err := api.load(primary)
	if profile != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.unload(primary, profile)) }()
	}
	if err != nil {
		return "", err
	}
	if profile == 0 {
		return "", fmt.Errorf("LoadUserProfileW returned no profile handle")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	home, err = api.directory(primary)
	if err != nil {
		return "", err
	}
	if home == "" {
		return "", fmt.Errorf("GetUserProfileDirectoryW returned an empty path")
	}
	if err := step(api.identity); err != nil {
		return "", err
	}
	return home, nil
}
