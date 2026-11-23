//go:build windows

package environment

import (
	"context"
	"encoding/json"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

// ProjectLocalWindowsTarget shares production target selection with an explicit
// identity-only lookup. It does not construct a repository or invoke account,
// token, profile or process APIs. SID text is normalized by the existing Windows
// SID parser; the Windows configuration/defaults remain platform-specific.
// Only selectors are projected: current account SID and metadata are not added
// to name-based v1 fingerprints. Functions and context getters remain caller
// capabilities, and this is not a login/provisioning/native-policy result.
func ProjectLocalWindowsTarget(ctx Context, conf *configuration.EnvironmentLocal, accounts windowslocal.IdentityLookup) (TargetProjection, error) {
	account, name, uid, err := resolveLocalWindowsTargetAccount(ctx, conf, accounts)
	// An unmodeled fact must not be masked by a joined not-found signal.
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded, windowslocal.ErrAccountNotModeled, windowslocal.ErrAccountLookupUnavailable, windowslocal.ErrInvalidAccountFacts} {
		if errors.Is(err, sentinel) {
			safe := sessionTargetError(errors.System, err, "cannot inspect local Windows session target account: %s", sentinel)
			safe.Cause = sentinel
			return TargetProjection{}, safe
		}
	}
	if err != nil && !errors.Is(err, windowslocal.ErrNotFound) {
		return TargetProjection{}, sessionTargetError(errors.System, err, "cannot inspect local Windows session target account")
	}
	if err == nil {
		name = account.Name
	}
	fields := collectLocalSessionTargetFields(newTargetProjectionFields(ctx), &conf.EnvironmentLocalCommon)
	fields.values["name"] = strings.ToLower(name)
	fields.values["requestedSID"] = uid
	fields.string("displayName", &conf.DisplayName)
	fields.string("skel", &conf.Skel)
	groups, err := conf.Groups.Render(ctx)
	if err != nil {
		return TargetProjection{}, sessionTargetError(errors.Config, err, "cannot resolve local Windows session target groups")
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return TargetProjection{}, sessionTargetError(errors.System, err, "cannot encode local Windows session target groups")
	}
	fields.values["groups"] = string(raw)
	return fields.projection("local-windows")
}

func resolveLocalWindowsTargetAccount(ctx Context, conf *configuration.EnvironmentLocal, accounts windowslocal.IdentityLookup) (account windowslocal.Account, name, uid string, err error) {
	if conf == nil {
		return account, "", "", errors.Config.Newf("local Windows target configuration is unavailable")
	}
	if nilLocalTargetDependency(ctx) || ctx.Context() == nil || nilLocalTargetDependency(accounts) {
		return account, "", "", windowslocal.ErrAccountLookupUnavailable
	}
	if err := ctx.Context().Err(); err != nil {
		return account, "", "", errors.System.Newf("%w", err)
	}
	if name, err = conf.Name.Render(ctx); err != nil {
		return account, "", "", errors.Config.Newf("cannot evaluate local account name: %w", err)
	}
	if uid, err = conf.Uid.Render(ctx); err != nil {
		return account, "", "", errors.Config.Newf("cannot evaluate local account UID: %w", err)
	}
	if name == "" && uid == "" {
		return account, "", "", errors.Config.Newf("local account name or UID is required")
	}
	if name != "" && !validLocalSAMName(name) {
		return account, "", "", errors.Config.Newf("invalid local SAM account name")
	}
	if uid != "" {
		sid, parseErr := windows.StringToSid(uid)
		if parseErr != nil || sid == nil || !sid.IsValid() {
			return account, "", "", errors.Config.Newf("invalid local account UID")
		}
		uid = sid.String()
	}
	account.Name, account.SID, err = windowslocal.ResolveIdentity(ctx.Context(), accounts, name, uid)
	return account, name, uid, err
}

// The production adapter uses the existing local-SAM lookup functions only.
// No native account object/getter is returned across the lookup boundary.
type localWindowsAccountLookup struct{}

func (localWindowsAccountLookup) LookupIdentityByName(_ context.Context, name string) (string, string, error) {
	account, err := lookupLocalWindowsAccount(name)
	return localWindowsLookupIdentity(account, err)
}

func (localWindowsAccountLookup) LookupIdentityBySID(_ context.Context, sid string) (string, string, error) {
	account, err := lookupLocalWindowsAccountByUID(sid)
	return localWindowsLookupIdentity(account, err)
}

func localWindowsLookupIdentity(account windowsLocalAccount, err error) (string, string, error) {
	if errors.Is(err, errLocalWindowsAccountNotFound) {
		return "", "", windowslocal.ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	return account.Name, account.SID, nil
}
