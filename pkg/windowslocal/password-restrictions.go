package windowslocal

import (
	"context"
	"errors"
	"fmt"
)

var errSAMPasswordRestriction = errors.New("native SAM password restriction denied")

// All operations must read fresh state for the same bound local name/SID. The
// Windows binding runs this synchronous flow inside the isolated System guard.
// Passing these restrictions is not a resume authorization: group/template,
// target, operator-method, session, revocation and grant checks remain external.
type samPasswordRestrictionOperations struct {
	system        func() error
	identity      func() error
	accountState  func() error
	blankPassword func() (bool, error)
	blankNetwork  func() (bool, error)
	s4u           func() (uintptr, error)
	tokenIdentity func(uintptr) error
	closeToken    func(uintptr) error
}

func checkSAMPasswordRestrictionsFlow(ctx context.Context, allowEmpty bool, api samPasswordRestrictionOperations) (resultErr error) {
	if ctx == nil {
		return fmt.Errorf("missing native SAM password-restriction context")
	}
	defer func() { resultErr = errors.Join(resultErr, ctx.Err()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if api.system == nil || api.identity == nil || api.accountState == nil || api.blankPassword == nil || api.blankNetwork == nil || api.s4u == nil || api.tokenIdentity == nil || api.closeToken == nil {
		return fmt.Errorf("incomplete native SAM password-restriction operations")
	}
	step := func(action func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.Join(action(), ctx.Err())
	}
	restrictions := func() error {
		if err := step(api.identity); err != nil {
			return err
		}
		if err := step(api.accountState); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		blank, err := api.blankPassword()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		restricted, err := api.blankNetwork()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if blank && (!allowEmpty || restricted) {
			return errSAMPasswordRestriction
		}
		return step(api.identity)
	}
	if err := step(api.system); err != nil {
		return err
	}
	if err := restrictions(); err != nil {
		return err
	}
	// Retain and close even an unexpected token returned together with an error.
	// Complete token cleanup before the final fresh restriction/identity checks.
	if err := func() (resultErr error) {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := api.s4u()
		if token != 0 {
			defer func() { resultErr = errors.Join(resultErr, api.closeToken(token), ctx.Err()) }()
		}
		if err != nil {
			return err
		}
		if token == 0 {
			return fmt.Errorf("native S4U restriction check returned no token")
		}
		return step(func() error { return api.tokenIdentity(token) })
	}(); err != nil {
		return err
	}
	if err := restrictions(); err != nil {
		return err
	}
	return step(api.system)
}
