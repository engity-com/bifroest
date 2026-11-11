package windowslocal

import (
	"context"
	"errors"
	"fmt"
)

// Native handles remain opaque to this synchronous ownership flow. A successful
// token transfers to its caller only after profile cleanup and deregistration;
// the caller must still verify its SID, current account and applicable policy.
type s4uLogonOutput struct {
	token   uintptr
	profile uintptr
}

type s4uTokenOperations struct {
	register      func() (uintptr, error)
	lookupPackage func(uintptr) (uint32, error)
	allocateLUID  func() error
	logon         func(uintptr, uint32) (s4uLogonOutput, error)
	freeProfile   func(uintptr) error
	deregister    func(uintptr) error
	closeToken    func(uintptr) error
}

func acquireS4UToken(ctx context.Context, api s4uTokenOperations) (result uintptr, resultErr error) {
	if ctx == nil {
		return 0, fmt.Errorf("missing local S4U context")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if api.register == nil || api.lookupPackage == nil || api.allocateLUID == nil || api.logon == nil || api.freeProfile == nil || api.deregister == nil || api.closeToken == nil {
		return 0, fmt.Errorf("incomplete local S4U operations")
	}
	var token uintptr
	defer func() {
		resultErr = errors.Join(resultErr, ctx.Err())
		if resultErr != nil {
			result = 0
			if token != 0 {
				resultErr = errors.Join(resultErr, api.closeToken(token), ctx.Err())
			}
		}
	}()
	handle, err := api.register()
	if handle != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.deregister(handle)) }()
	}
	if err != nil {
		return 0, err
	}
	if handle == 0 {
		return 0, fmt.Errorf("LsaRegisterLogonProcess returned no handle")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	packageID, err := api.lookupPackage(handle)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := api.allocateLUID(); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	output, err := api.logon(handle, packageID)
	token = output.token
	if output.profile != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.freeProfile(output.profile)) }()
	}
	if err != nil {
		return 0, err
	}
	if token == 0 {
		return 0, fmt.Errorf("LsaLogonUser returned no token")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return token, nil
}
