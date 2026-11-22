package windowslocal

import (
	"context"
	"reflect"

	"github.com/engity-com/bifroest/pkg/errors"
)

// ResolveIdentity shares local target selection with an explicitly supplied
// read-only lookup. A name takes precedence, but a supplied canonical SID must
// still match the result. Unlike Unix name-based selection, Windows does not
// ignore a simultaneously supplied numeric identity. No second lookup/fallback
// is made. SID syntax/normalization is the caller's platform/fixture boundary;
// this function never parses SDDL aliases or discovers account scope/host data.
// ErrNotFound, unmodeled observations and source failures remain distinct.
func ResolveIdentity(ctx context.Context, accounts IdentityLookup, name, sid string) (string, string, error) {
	if ctx == nil || accounts == nil || nilIdentityLookup(accounts) {
		return "", "", ErrAccountLookupUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", "", errors.System.Newf("%w", err)
	}
	if name == "" && sid == "" || name != "" && !validName(name) {
		return "", "", ErrInvalidAccountFacts
	}
	var resolvedName, resolvedSID string
	var err error
	if name != "" {
		resolvedName, resolvedSID, err = accounts.LookupIdentityByName(ctx, name)
	} else {
		resolvedName, resolvedSID, err = accounts.LookupIdentityBySID(ctx, sid)
	}
	if canceled := ctx.Err(); canceled != nil {
		return "", "", errors.System.Newf("%w", canceled)
	}
	if err != nil {
		return "", "", err
	}
	if !validName(resolvedName) || !validAccountFactIdentity(resolvedSID) {
		return "", "", ErrInvalidAccountFacts
	}
	if sid != "" && resolvedSID != sid {
		return "", "", errors.Config.Newf("local account does not match UID: %w", ErrInvalidAccountFacts)
	}
	return resolvedName, resolvedSID, nil
}

func nilIdentityLookup(value IdentityLookup) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
