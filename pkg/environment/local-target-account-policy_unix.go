//go:build unix

package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/user"
)

const unixLoginShellsFile = "/etc/shells"

func (this *LocalRepository) resolveTargetAccount(ctx Context) (any, bool, error) {
	if authorization.KindOf(ctx.Authorization()) == "none" && !this.conf.TargetAccountPolicy.AllowUnsafeNoneAuthorization {
		return nil, false, nil
	}
	target, err := this.lookupTargetAccount(ctx)
	if err != nil {
		return nil, false, errors.Newf(errors.System, "cannot resolve Unix target account: %w", err)
	}
	if target == nil {
		return nil, true, nil
	}
	accepted, err := this.isTargetAccountAccepted(target)
	if err != nil || !accepted {
		return target, accepted, err
	}
	if !this.isAuthorizationTargetAccountBound(ctx, target) {
		return target, false, nil
	}
	return target, true, nil
}

func (*LocalRepository) isAuthorizationTargetAccountBound(ctx Context, target *user.User) bool {
	if authorization.KindOf(ctx.Authorization()) != "local" {
		return true
	}
	authenticated := authorization.LocalUserOf(ctx.Authorization())
	return authenticated != nil && target != nil && authenticated.Uid == target.Uid
}

func (*LocalRepository) localTokenAuthorizationKind(req Request) string {
	return authorization.KindOf(req.Authorization())
}

func (this *LocalRepository) isTargetAccountAccepted(target *user.User) (bool, error) {
	if target == nil {
		return false, errors.Newf(errors.System, "resolved Unix target account is nil")
	}
	if err := this.validateTargetAccount(target); err != nil {
		if errors.Permission.IsErr(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (this *LocalRepository) isStoredTargetAccountAccepted(ctx context.Context, target *user.User, token *localToken) (bool, error) {
	if target == nil || token == nil || token.User.Name == "" || token.User.Uid == nil {
		return false, errors.Newf(errors.System, "stored Unix target account identity is incomplete")
	}
	if target.Name != token.User.Name || target.Uid != *token.User.Uid {
		return false, nil
	}
	byUid, err := this.userRepository.LookupById(ctx, *token.User.Uid)
	if errors.Is(err, user.ErrNoSuchUser) {
		return false, nil
	}
	if err != nil {
		return false, errors.Newf(errors.System, "cannot resolve stored Unix target account by UID: %w", err)
	}
	if byUid == nil || byUid.Name != token.User.Name || byUid.Uid != *token.User.Uid {
		return false, nil
	}
	if token.AuthorizationKind == "" {
		if !acceptLegacyEnvironmentTokenWithoutAuthorizationKind() {
			return false, errors.Newf(errors.System, "stored Unix target account authorization kind is missing")
		}
	} else if token.AuthorizationKind == "none" && !this.conf.TargetAccountPolicy.AllowUnsafeNoneAuthorization {
		return false, nil
	}
	return true, nil
}

func (*LocalRepository) isCurrentTargetAccount(expected any, actual *user.User) bool {
	target, ok := expected.(*user.User)
	return ok && target != nil && actual != nil && target.Name == actual.Name && target.Uid == actual.Uid
}

func (this *LocalRepository) validateTargetAccount(target *user.User) error {
	policy := &this.conf.TargetAccountPolicy
	groups := append(user.Groups{target.Group}, target.Groups...)

	if slices.Contains(policy.DeniedNames, target.Name) || slices.Contains(policy.DeniedUids, target.Uid) {
		return errors.Newf(errors.Permission, "Unix target account %s is denied by policy", target)
	}
	for _, group := range groups {
		if slices.Contains(policy.DeniedGroups, group.Name) || slices.Contains(policy.DeniedGids, group.Gid) {
			return errors.Newf(errors.Permission, "Unix target account %s has denied group %s", target, group)
		}
	}

	if len(policy.AllowedNames) > 0 && !slices.Contains(policy.AllowedNames, target.Name) {
		return errors.Newf(errors.Permission, "Unix target account %s is not in the account-name allowlist", target)
	}
	if len(policy.AllowedUids) > 0 && !slices.Contains(policy.AllowedUids, target.Uid) {
		return errors.Newf(errors.Permission, "Unix target account %s is not in the UID allowlist", target)
	}
	if len(policy.AllowedGroups) > 0 && !containsUnixGroupName(groups, policy.AllowedGroups) {
		return errors.Newf(errors.Permission, "Unix target account %s has no group in the group-name allowlist", target)
	}
	if len(policy.AllowedGids) > 0 && !containsUnixGroupId(groups, policy.AllowedGids) {
		return errors.Newf(errors.Permission, "Unix target account %s has no group in the GID allowlist", target)
	}

	if target.Uid == 0 && !policy.AllowUidZero {
		return errors.Newf(errors.Permission, "Unix target account %s has UID 0", target)
	}
	if strings.HasPrefix(target.Name, "_") && !policy.AllowSystemAccounts {
		return errors.Newf(errors.Permission, "Unix system target account %s is not allowed", target)
	}
	if containsUnixGroupName(groups, []string{"admin"}) && !policy.AllowAdministrators {
		return errors.Newf(errors.Permission, "Unix administrator target account %s is not allowed", target)
	}

	if !policy.AllowNonLoginShell {
		validate := this.targetAccountShellValidator
		if validate == nil {
			validate = func(shell string) error {
				return validateUnixLoginShell(shell, unixLoginShellsFile)
			}
		}
		if err := validate(target.Shell); err != nil {
			return err
		}
	}
	return nil
}

func (this *local) revalidateTargetAccount(ctx context.Context) error {
	byName, err := this.repository.userRepository.LookupByName(ctx, this.user.Name)
	if err != nil {
		return errors.Newf(errors.System, "cannot revalidate Unix target account %q by name: %w", this.user.Name, err)
	}
	byUid, err := this.repository.userRepository.LookupById(ctx, this.user.Uid)
	if err != nil {
		return errors.Newf(errors.System, "cannot revalidate Unix target account UID %d: %w", this.user.Uid, err)
	}
	if !sameUnixTargetAccount(this.user, byName) || !sameUnixTargetAccount(this.user, byUid) {
		return errors.Newf(errors.Permission, "Unix target account %s changed before process start", this.user)
	}
	if err := this.repository.validateTargetAccount(byName); err != nil {
		return fmt.Errorf("Unix target account failed pre-start policy revalidation: %w", err)
	}
	return nil
}

func validateUnixLoginShell(shell, shellsFile string) error {
	if shell == "" {
		return errors.Newf(errors.Permission, "Unix target account has an empty login shell")
	}
	if base := filepath.Base(shell); base == "false" || base == "nologin" {
		return errors.Newf(errors.Permission, "Unix target account has non-login shell %q", shell)
	}
	if !filepath.IsAbs(shell) {
		return errors.Newf(errors.Permission, "Unix target account login shell %q is not absolute", shell)
	}
	info, err := os.Stat(shell)
	if err != nil {
		return errors.Newf(errors.Permission, "cannot use Unix target account login shell %q: %v", shell, err)
	}
	if !info.Mode().IsRegular() {
		return errors.Newf(errors.Permission, "Unix target account login shell %q is not a regular file", shell)
	}
	if info.Mode().Perm()&0111 == 0 {
		return errors.Newf(errors.Permission, "Unix target account login shell %q is not executable", shell)
	}

	file, err := os.Open(shellsFile)
	if err != nil {
		return errors.Newf(errors.System, "cannot read Unix login-shell allowlist %q: %w", shellsFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == shell {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.Newf(errors.System, "cannot scan Unix login-shell allowlist %q: %w", shellsFile, err)
	}
	return errors.Newf(errors.Permission, "Unix target account login shell %q is not listed in %s", shell, shellsFile)
}

func containsUnixGroupName(groups user.Groups, allowed []string) bool {
	for _, group := range groups {
		if slices.Contains(allowed, group.Name) {
			return true
		}
	}
	return false
}

func containsUnixGroupId(groups user.Groups, allowed []user.GroupId) bool {
	for _, group := range groups {
		if slices.Contains(allowed, group.Gid) {
			return true
		}
	}
	return false
}

func sameUnixTargetAccount(expected, actual *user.User) bool {
	if expected == nil || actual == nil ||
		expected.Name != actual.Name || expected.DisplayName != actual.DisplayName || expected.Uid != actual.Uid ||
		!expected.Group.IsEqualTo(actual.Group) ||
		expected.Shell != actual.Shell || expected.HomeDir != actual.HomeDir ||
		len(expected.Groups) != len(actual.Groups) {
		return false
	}
	for _, expectedGroup := range expected.Groups {
		if !actual.Groups.Contains(&expectedGroup) {
			return false
		}
	}
	return true
}
