//go:build darwin

package environment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/user"
)

const darwinLoginShellsFile = "/etc/shells"

func (this *LocalRepository) willTargetAccountBeAccepted(ctx Context) (bool, error) {
	target, err := this.lookupUserBy(ctx)
	if err != nil {
		return false, errors.Newf(errors.System, "cannot resolve Darwin target account: %w", err)
	}
	return this.isTargetAccountAccepted(target)
}

func (this *LocalRepository) isTargetAccountAccepted(target *user.User) (bool, error) {
	if target == nil {
		return false, errors.Newf(errors.System, "resolved Darwin target account is nil")
	}
	if err := this.validateTargetAccount(target); err != nil {
		if errors.Permission.IsErr(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (this *LocalRepository) isStoredTargetAccountAccepted(target *user.User, token *localToken) (bool, error) {
	if target == nil || token == nil || token.User.Name == "" || token.User.Uid == nil {
		return false, errors.Newf(errors.System, "stored Darwin target account identity is incomplete")
	}
	return target.Name == token.User.Name && target.Uid == *token.User.Uid, nil
}

func (this *LocalRepository) validateTargetAccount(target *user.User) error {
	policy := &this.conf.TargetAccountPolicy
	groups := append(user.Groups{target.Group}, target.Groups...)

	if slices.Contains(policy.DeniedNames, target.Name) || slices.Contains(policy.DeniedUids, target.Uid) {
		return errors.Newf(errors.Permission, "Darwin target account %s is denied by policy", target)
	}
	for _, group := range groups {
		if slices.Contains(policy.DeniedGroups, group.Name) || slices.Contains(policy.DeniedGids, group.Gid) {
			return errors.Newf(errors.Permission, "Darwin target account %s has denied group %s", target, group)
		}
	}

	if len(policy.AllowedNames) > 0 && !slices.Contains(policy.AllowedNames, target.Name) {
		return errors.Newf(errors.Permission, "Darwin target account %s is not in the account-name allowlist", target)
	}
	if len(policy.AllowedUids) > 0 && !slices.Contains(policy.AllowedUids, target.Uid) {
		return errors.Newf(errors.Permission, "Darwin target account %s is not in the UID allowlist", target)
	}
	if len(policy.AllowedGroups) > 0 && !containsDarwinGroupName(groups, policy.AllowedGroups) {
		return errors.Newf(errors.Permission, "Darwin target account %s has no group in the group-name allowlist", target)
	}
	if len(policy.AllowedGids) > 0 && !containsDarwinGroupId(groups, policy.AllowedGids) {
		return errors.Newf(errors.Permission, "Darwin target account %s has no group in the GID allowlist", target)
	}

	if target.Uid == 0 && !policy.AllowUidZero {
		return errors.Newf(errors.Permission, "Darwin target account %s has UID 0", target)
	}
	if strings.HasPrefix(target.Name, "_") && !policy.AllowSystemAccounts {
		return errors.Newf(errors.Permission, "Darwin system target account %s is not allowed", target)
	}
	if containsDarwinGroupName(groups, []string{"admin"}) && !policy.AllowAdministrators {
		return errors.Newf(errors.Permission, "Darwin administrator target account %s is not allowed", target)
	}

	if !policy.AllowNonLoginShell {
		validate := this.targetAccountShellValidator
		if validate == nil {
			validate = func(shell string) error {
				return validateDarwinLoginShell(shell, darwinLoginShellsFile)
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
		return errors.Newf(errors.System, "cannot revalidate Darwin target account %q by name: %w", this.user.Name, err)
	}
	byUid, err := this.repository.userRepository.LookupById(ctx, this.user.Uid)
	if err != nil {
		return errors.Newf(errors.System, "cannot revalidate Darwin target account UID %d: %w", this.user.Uid, err)
	}
	if !sameDarwinTargetAccount(this.user, byName) || !sameDarwinTargetAccount(this.user, byUid) {
		return errors.Newf(errors.Permission, "Darwin target account %s changed before process start", this.user)
	}
	if err := this.repository.validateTargetAccount(byName); err != nil {
		return fmt.Errorf("Darwin target account failed pre-start policy revalidation: %w", err)
	}
	return nil
}

func validateDarwinLoginShell(shell, shellsFile string) error {
	if shell == "" {
		return errors.Newf(errors.Permission, "Darwin target account has an empty login shell")
	}
	if base := filepath.Base(shell); base == "false" || base == "nologin" {
		return errors.Newf(errors.Permission, "Darwin target account has non-login shell %q", shell)
	}
	if !filepath.IsAbs(shell) {
		return errors.Newf(errors.Permission, "Darwin target account login shell %q is not absolute", shell)
	}
	info, err := os.Stat(shell)
	if err != nil {
		return errors.Newf(errors.Permission, "cannot use Darwin target account login shell %q: %v", shell, err)
	}
	if !info.Mode().IsRegular() {
		return errors.Newf(errors.Permission, "Darwin target account login shell %q is not a regular file", shell)
	}
	if info.Mode().Perm()&0111 == 0 {
		return errors.Newf(errors.Permission, "Darwin target account login shell %q is not executable", shell)
	}

	file, err := os.Open(shellsFile)
	if err != nil {
		return errors.Newf(errors.System, "cannot read Darwin login-shell allowlist %q: %w", shellsFile, err)
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
		return errors.Newf(errors.System, "cannot scan Darwin login-shell allowlist %q: %w", shellsFile, err)
	}
	return errors.Newf(errors.Permission, "Darwin target account login shell %q is not listed in %s", shell, shellsFile)
}

func containsDarwinGroupName(groups user.Groups, allowed []string) bool {
	for _, group := range groups {
		if slices.Contains(allowed, group.Name) {
			return true
		}
	}
	return false
}

func containsDarwinGroupId(groups user.Groups, allowed []user.GroupId) bool {
	for _, group := range groups {
		if slices.Contains(allowed, group.Gid) {
			return true
		}
	}
	return false
}

func sameDarwinTargetAccount(expected, actual *user.User) bool {
	if expected == nil || actual == nil ||
		expected.Name != actual.Name || expected.Uid != actual.Uid ||
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
