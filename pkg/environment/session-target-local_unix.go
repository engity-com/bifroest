//go:build unix

package environment

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalRepository) targetAccount(ctx Context) (*user.Requirement, *localTargetAccountIdentity, error) {
	return resolveLocalUnixTargetAccount(ctx, this.conf, localUnixAccountLookup{users: this.userRepository})
}

func (this *LocalRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	projection, err := ProjectLocalUnixTarget(ctx, this.conf, localUnixAccountLookup{users: this.userRepository})
	if err != nil {
		return "", err
	}
	// Names remain stable across deferred account creation. Reuse additionally
	// checks the persisted UID against the current account to detect replacement.
	return projection.SessionTarget()
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
