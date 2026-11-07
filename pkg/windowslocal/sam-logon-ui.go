package windowslocal

import (
	"context"
	"errors"
	"fmt"
)

// Shared by actual Windows query bindings and portable failure models. These
// are only two nonsecret observations, never an account-policy eligibility.
type observedSAMLogonUI struct {
	PasswordIsBlank bool `json:"passwordIsBlank"`
	AccountDisabled bool `json:"accountDisabled"`
}

type samLogonUIValue struct{ PasswordIsBlank, AccountIsDisabled uint8 }

type samLogonUIOperations struct {
	identity   func() error
	connect    func() (uintptr, error)
	openDomain func(uintptr) (uintptr, error)
	openUser   func(uintptr) (uintptr, error)
	query      func(uintptr) (*samLogonUIValue, error)
	free       func(*samLogonUIValue) error
	close      func(uintptr) error
}

// Every call is synchronous. Cleanup is registered even when an API supplies a
// resource together with an error. The outer defer runs after every cleanup and
// discards observations on any native, identity, cleanup or context failure.
func observeSAMLogonUIFlow(ctx context.Context, api samLogonUIOperations) (result *observedSAMLogonUI, resultErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("missing SAM logon-UI observation context")
	}
	defer func() {
		// Also cover identity changes while native resources were being freed.
		// Never start another identity lookup after a failed/canceled operation.
		if resultErr == nil && ctx.Err() == nil && result != nil {
			resultErr = api.identity()
		}
		resultErr = errors.Join(resultErr, ctx.Err())
		if resultErr != nil {
			result = nil
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if api.identity == nil || api.connect == nil || api.openDomain == nil || api.openUser == nil || api.query == nil || api.free == nil || api.close == nil {
		return nil, fmt.Errorf("incomplete SAM observation operations")
	}
	if err := api.identity(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	server, err := api.connect()
	if server != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.close(server)) }()
	}
	if err != nil {
		return nil, err
	}
	if server == 0 {
		return nil, fmt.Errorf("SamConnect returned no handle")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	domain, err := api.openDomain(server)
	if domain != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.close(domain)) }()
	}
	if err != nil {
		return nil, err
	}
	if domain == 0 {
		return nil, fmt.Errorf("SamOpenDomain returned no handle")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	user, err := api.openUser(domain)
	if user != 0 {
		defer func() { resultErr = errors.Join(resultErr, api.close(user)) }()
	}
	if err != nil {
		return nil, err
	}
	if user == 0 {
		return nil, fmt.Errorf("SamOpenUser returned no handle")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, err := api.query(user)
	if value != nil {
		defer func() { resultErr = errors.Join(resultErr, api.free(value)) }()
	}
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, fmt.Errorf("SamQueryInformationUser returned no logon-UI data")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if value.PasswordIsBlank > 1 || value.AccountIsDisabled > 1 {
		return nil, fmt.Errorf("unsupported SAM logon-UI BOOLEAN layout")
	}
	if err := api.identity(); err != nil {
		return nil, err
	}
	result = &observedSAMLogonUI{PasswordIsBlank: value.PasswordIsBlank != 0, AccountDisabled: value.AccountIsDisabled != 0}
	return result, nil
}
