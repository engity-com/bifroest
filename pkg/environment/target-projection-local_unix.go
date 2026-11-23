//go:build unix

package environment

import (
	"context"
	"encoding/json"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/user"
)

// ProjectLocalUnixTarget shares production target selection with an explicit
// read-only identity lookup. It constructs no account repository or credentials.
// The account field retains the legacy JSON-encoded requirement selector; it is
// not the current account's metadata or a complete provisioning/policy result.
// In particular, the current UID is not added to name-based v1 fingerprints.
// Template functions/context getters remain caller capabilities.
func ProjectLocalUnixTarget(ctx Context, conf *configuration.EnvironmentLocal, accounts user.IdentityLookup) (TargetProjection, error) {
	requested, account, err := resolveLocalUnixTargetAccount(ctx, conf, accounts)
	if err != nil {
		return TargetProjection{}, err
	}
	if account != nil {
		requested.Name = account.Name
	}
	raw, err := json.Marshal(requested)
	if err != nil {
		return TargetProjection{}, sessionTargetError(errors.System, err, "cannot encode local session target account")
	}
	fields := collectLocalSessionTargetFields(newTargetProjectionFields(ctx), &conf.EnvironmentLocalCommon)
	fields.values["account"] = string(raw)
	return fields.projection("local-unix")
}

type localTargetAccountIdentity struct {
	Name string
	Uid  user.Id
}

func resolveLocalUnixTargetAccount(ctx Context, conf *configuration.EnvironmentLocal, accounts user.IdentityLookup) (*user.Requirement, *localTargetAccountIdentity, error) {
	if conf == nil {
		return nil, nil, errors.Config.Newf("local target configuration is unavailable")
	}
	if nilLocalTargetDependency(accounts) || nilLocalTargetDependency(ctx) || ctx.Context() == nil {
		return nil, nil, user.ErrAccountLookupUnavailable
	}
	if err := ctx.Context().Err(); err != nil {
		return nil, nil, errors.System.Newf("%w", err)
	}
	requested, err := conf.User.Render(nil, ctx)
	if err != nil {
		return nil, nil, sessionTargetError(errors.Config, err, "cannot resolve local session target account")
	}
	var name string
	var uid user.Id
	if requested.Name != "" {
		name, uid, err = accounts.LookupIdentityByName(ctx.Context(), requested.Name)
	} else if requested.Uid != nil {
		name, uid, err = accounts.LookupIdentityById(ctx.Context(), *requested.Uid)
	} else {
		return nil, nil, errors.Config.Newf("local target needs an account name or UID")
	}
	if canceled := ctx.Context().Err(); canceled != nil {
		return nil, nil, errors.System.Newf("%w", canceled)
	}
	// Preserve safe sentinels, never provider error text or a sensitive cause.
	// A missing observation must not be masked by a joined not-found error.
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded, user.ErrAccountNotModeled, user.ErrAccountLookupUnavailable, user.ErrInvalidAccountFacts} {
		if errors.Is(err, sentinel) {
			safe := sessionTargetError(errors.System, err, "cannot inspect local session target account: %s", sentinel)
			safe.Cause = sentinel
			return nil, nil, safe
		}
	}
	if errors.Is(err, user.ErrNoSuchUser) {
		return requested, nil, nil
	}
	if err != nil {
		return nil, nil, sessionTargetError(errors.System, err, "cannot inspect local session target account")
	}
	if name == "" || requested.Name == "" && uid != *requested.Uid {
		return nil, nil, errors.Config.Newf("cannot inspect local session target account: %w", user.ErrInvalidAccountFacts)
	}
	return requested, &localTargetAccountIdentity{Name: name, Uid: uid}, nil
}

// The production adapter deliberately exposes only identities, never native
// account getters or mutation methods. It reuses the already owned repository.
type localUnixAccountLookup struct {
	users interface {
		LookupByName(context.Context, string) (*user.User, error)
		LookupById(context.Context, user.Id) (*user.User, error)
	}
}

func (this localUnixAccountLookup) LookupIdentityByName(ctx context.Context, name string) (string, user.Id, error) {
	if nilLocalTargetDependency(this.users) {
		return "", 0, user.ErrAccountLookupUnavailable
	}
	account, err := this.users.LookupByName(ctx, name)
	return localUnixLookupIdentity(account, err)
}

func (this localUnixAccountLookup) LookupIdentityById(ctx context.Context, id user.Id) (string, user.Id, error) {
	if nilLocalTargetDependency(this.users) {
		return "", 0, user.ErrAccountLookupUnavailable
	}
	account, err := this.users.LookupById(ctx, id)
	return localUnixLookupIdentity(account, err)
}

func localUnixLookupIdentity(account *user.User, err error) (string, user.Id, error) {
	if err != nil {
		return "", 0, err
	}
	if account == nil || account.Name == "" {
		return "", 0, user.ErrInvalidAccountFacts
	}
	return account.Name, account.Uid, nil
}
