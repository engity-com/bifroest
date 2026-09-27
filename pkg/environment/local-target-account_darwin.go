//go:build darwin

package environment

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalRepository) lookupTargetAccount(ctx Context) (*user.User, error) {
	var target *user.User
	var err error
	if name := this.conf.User.Name; !name.IsZero() {
		target, err = this.lookupByName(ctx, name)
	} else if uid := this.conf.User.Uid; uid != nil {
		target, err = this.lookupByUid(ctx, *uid)
	} else {
		target, err = this.userRepository.LookupByName(ctx.Context(), ctx.Connection().Remote().User())
	}
	if err != nil {
		return nil, err
	}

	requirement, err := this.conf.User.Render(nil, ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot render user requirement: %w", err)
	}
	if err := userFulfilsRequirement(target, requirement); err != nil {
		return nil, err
	}
	return target, nil
}

func (this *LocalRepository) resolveUserForEnsure(req Request, _ *localEnsureOpts) (*user.User, bool, error) {
	target, err := this.lookupTargetAccount(req)
	return target, false, err
}

func acceptLegacyEnvironmentTokenWithoutAuthorizationKind() bool {
	return false
}

func userFulfilsRequirement(actual *user.User, required *user.Requirement) error {
	mismatch := func(field string) error {
		return fmt.Errorf("%w: Unix target account does not match required %s", user.ErrUserDoesNotFulfilRequirement, field)
	}
	if actual == nil || required == nil {
		return mismatch("user")
	}
	if required.Name != "" && actual.Name != required.Name {
		return mismatch("name")
	}
	if required.DisplayName != "" && actual.DisplayName != required.DisplayName {
		return mismatch("display name")
	}
	if required.Uid != nil && actual.Uid != *required.Uid {
		return mismatch("UID")
	}
	if required.Group.Name != "" && actual.Group.Name != required.Group.Name ||
		required.Group.Gid != nil && actual.Group.Gid != *required.Group.Gid {
		return mismatch("primary group")
	}
	if len(required.Groups) > 0 && !supplementaryGroupsFulfilRequirement(actual.Groups, required.Groups) {
		return mismatch("supplementary groups")
	}
	if required.Shell != "" && actual.Shell != required.Shell {
		return mismatch("shell")
	}
	if required.HomeDir != "" && actual.HomeDir != required.HomeDir {
		return mismatch("home directory")
	}
	if required.Skel != "" {
		return mismatch("skeleton directory")
	}
	return nil
}

func supplementaryGroupsFulfilRequirement(actual user.Groups, required user.GroupRequirements) bool {
	if len(actual) != len(required) {
		return false
	}
	matched := make([]bool, len(actual))
	for _, requirement := range required {
		found := false
		for i, group := range actual {
			if !matched[i] &&
				(requirement.Name == "" || requirement.Name == group.Name) &&
				(requirement.Gid == nil || *requirement.Gid == group.Gid) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
