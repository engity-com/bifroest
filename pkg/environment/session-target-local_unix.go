//go:build unix

package environment

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalRepository) targetAccount(ctx Context) (*user.Requirement, *user.User, error) {
	requested, err := this.conf.User.Render(nil, ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot resolve local session target account")
	}
	var account *user.User
	if requested.Name != "" {
		account, err = this.userRepository.LookupByName(ctx.Context(), requested.Name)
	} else if requested.Uid != nil {
		account, err = this.userRepository.LookupById(ctx.Context(), *requested.Uid)
	} else {
		return nil, nil, fmt.Errorf("local target needs an account name or UID")
	}
	if errors.Is(err, user.ErrNoSuchUser) {
		return requested, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("cannot inspect local session target account")
	}
	return requested, account, nil
}

func (this *LocalRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	requested, account, err := this.targetAccount(ctx)
	if err != nil {
		return "", err
	}
	// Names remain stable across deferred account creation. Reuse additionally
	// checks the persisted UID against the current account to detect replacement.
	if account != nil {
		requested.Name = account.Name
	}
	raw, err := json.Marshal(requested)
	if err != nil {
		return "", fmt.Errorf("cannot encode local session target account")
	}
	fields := localSessionTargetFields(ctx, &this.conf.EnvironmentLocalCommon)
	fields.values["account"] = string(raw)
	return fields.target("local-unix")
}

func (this *LocalRepository) IsSessionCompatibleWith(ctx Context, sess session.Session) (bool, error) {
	requested, account, err := this.targetAccount(ctx)
	if err != nil {
		return false, err
	}
	raw, err := sess.EnvironmentToken(ctx.Context())
	if err != nil {
		return false, err
	}
	if len(raw) == 0 {
		return true, nil
	}
	var stored localToken
	if err := json.Unmarshal(raw, &stored); err != nil {
		return false, fmt.Errorf("cannot inspect local session target token")
	}
	if account == nil || (stored.User.Name != "" && stored.User.Name != account.Name) {
		return false, nil
	}
	if stored.User.Uid == nil {
		association, err := session.AssociationOf(ctx.Context(), sess)
		if err != nil && !errors.Is(err, session.ErrAssociationUnavailable) {
			return false, err
		}
		// Older name-only tokens retain their prior lookup semantics, but a
		// newly bound session must not silently lose its persisted UID evidence.
		if association != nil || stored.User.Name == "" {
			return false, nil
		}
	} else if *stored.User.Uid != account.Uid {
		return false, nil
	}
	if requested.Uid != nil && *requested.Uid != account.Uid {
		return false, nil
	}
	return true, nil
}
