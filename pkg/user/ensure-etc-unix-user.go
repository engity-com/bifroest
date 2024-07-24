//go:build moo && unix && !android

package user

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

func (this EtcUnixEnsurer) Ensure(req *Requirement, opts *EnsureOpts) (*User, error) {
	if req == nil {
		return nil, fmt.Errorf("nil user requirement")
	}
	target := req.Clone()
	_opts := opts.OrDefaults()

	if target.Group.IsZero() {
		target.Group = defaultGroup.Clone()
	}
	if target.Groups.IsZero() {
		target.Groups = GroupRequirements{target.Group}
	}
	if !target.Groups.Contains(&target.Group) {
		target.Groups = slices.Insert(target.Groups, 0, target.Group)
	}
	if len(target.Shell) == 0 {
		target.Shell = "/bin/sh"
	}

	return this.ensure(&target, &_opts)
}

func (this EtcUnixEnsurer) ensure(req *Requirement, opts *EnsureOpts) (*User, error) {
	fail := func(err error) (*User, error) {
		return nil, fmt.Errorf("cannot ensure user %v: %w", this, err)
	}
	failf := func(message string, args ...any) (*User, error) {
		return fail(fmt.Errorf(message, args...))
	}

	if req.Uid == 0 && len(req.Name) == 0 {
		return failf("user requirement with neither UID nor name")
	}

	var existing *User
	var err error
	if req.Uid > 0 {
		if existing, err = LookupUid(req.Uid, this.AllowBadNames, this.SkipIllegalEntries); err != nil {
			return nil, err
		}
	}
	if existing == nil && len(req.Name) > 0 {
		if existing, err = Lookup(req.Name, this.AllowBadNames, this.SkipIllegalEntries); err != nil {
			return nil, err
		}
	}

	group, err := this.EnsureGroup(&req.Group, opts)
	if err != nil {
		return fail(err)
	}
	groups, err := this.ensureGroups(req.Groups, opts)
	if err != nil {
		return fail(err)
	}

	if existing == nil {
		if *opts.CreateAllowed {
			result, err := this.create(req, group, groups...)
			if err != nil {
				return fail(err)
			}
			return result, nil
		}
		return nil, nil
	}

	if req.DoesFulfil(existing) || !*opts.ModifyAllowed {
		return existing, nil
	}

	result, err := this.modify(req, existing, group, groups...)
	if err != nil {
		return fail(err)
	}
	return result, nil
}

func (this EtcUnixEnsurer) create(req *Requirement, group *Group, groups ...*Group) (*User, error) {
	fail := func(err error) (*User, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*User, error) {
		return fail(fmt.Errorf(message, args...))
	}

	var args []string
	if v := req.Uid; v > 0 {
		args = append(args, "-u", strconv.FormatUint(uint64(v), 10))
	}
	if v := req.HomeDir; len(v) > 0 {
		args = append(args, "-d", v)
	}
	if v := req.Skel; len(v) > 0 {
		args = append(args, "-k", v)
	}
	name := req.name()
	args = append(args,
		"--badname", "-m",
		"-c", req.DisplayName,
		"-g", strconv.FormatUint(uint64(group.Gid), 10),
		"-G", formatGidsOfGroups(groups...),
		"-s", req.Shell,
		name,
	)

	if err := this.Executor.Execute("useradd", args...); err != nil {
		return failf("cannot create user %s: %w", name, err)
	}

	result, err := Lookup(name, this.AllowBadNames, this.SkipIllegalEntries)
	if err != nil {
		return failf("cannot lookup user after it was created: %w", err)
	}
	if result == nil {
		return failf("user cannot be found after it was created")
	}

	return result, nil
}

func (this EtcUnixEnsurer) modify(req *Requirement, existing *User, group *Group, groups ...*Group) (*User, error) {
	fail := func(err error) (*User, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*User, error) {
		return fail(fmt.Errorf(message, args...))
	}

	var args []string
	var lookup func() (*User, error)
	if v := req.Name; len(v) > 0 {
		args = append(args, "-l", strings.Clone(v))
		lookup = func() (*User, error) {
			return Lookup(v, this.AllowBadNames, this.SkipIllegalEntries)
		}
	}
	if v := req.Uid; v > 0 {
		args = append(args, "-u", strconv.FormatUint(uint64(v), 10))
		lookup = func() (*User, error) {
			return LookupUid(v, this.AllowBadNames, this.SkipIllegalEntries)
		}
	}
	if lookup == nil {
		panic("neither uid nor name provided")
	}
	if v := req.HomeDir; len(v) > 0 && v != existing.HomeDir {
		args = append(args, "-m", "-d", v)
	}
	args = append(args,
		"--badname",
		"-c", req.DisplayName,
		"-g", strconv.FormatUint(uint64(group.Gid), 10),
		"-G", formatGidsOfGroups(groups...),
		"-s", req.Shell,
		existing.Name,
	)

	if err := this.Executor.Execute("usermod", args...); err != nil {
		return failf("cannot modify user %v: %w", existing, err)
	}

	result, err := lookup()
	if err != nil {
		return failf("cannot lookup user %v after it was modified: %w", existing, err)
	}
	if result == nil {
		return failf("user cannot be found after it was modified")
	}

	return result, nil
}
