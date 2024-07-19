package user

import (
	"fmt"
	"strconv"
	"strings"
)

func (this ExecutionBasedEnsurer) EnsureGroup(req *GroupRequirement, opts *EnsureOpts) (*Group, error) {
	if req == nil {
		return nil, fmt.Errorf("nil group requirement")
	}
	_opts := opts.OrDefaults()
	fail := func(err error) (*Group, error) {
		return nil, fmt.Errorf("cannot ensure group %v: %w", req, err)
	}
	failf := func(message string, args ...any) (*Group, error) {
		return fail(fmt.Errorf(message, args...))
	}

	var existing *Group
	var err error
	if v := req.Gid; v > 0 {
		if existing, err = LookupGid(v, this.AllowBadNames); err != nil {
			return nil, err
		}
	} else if v := req.Name; len(req.Name) > 0 {
		if existing, err = LookupGroup(v, this.AllowBadNames); err != nil {
			return nil, err
		}
	} else {
		return failf("group requirement with neither GID nor name")
	}

	if existing == nil {
		if *_opts.CreateAllowed {
			result, err := this.createGroup(req)
			if err != nil {
				return fail(err)
			}
			return result, nil
		}
		return nil, nil
	}

	if req.DoesFulfil(existing) || !*_opts.ModifyAllowed {
		return existing, nil
	}

	result, err := this.modifyGroup(req, existing)
	if err != nil {
		return fail(err)
	}
	return result, nil
}

func (this ExecutionBasedEnsurer) createGroup(req *GroupRequirement) (*Group, error) {
	fail := func(err error) (*Group, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*Group, error) {
		return fail(fmt.Errorf(message, args...))
	}

	var args []string
	if v := req.Gid; v > 0 {
		args = append(args, "-g", strconv.FormatUint(uint64(v), 10))
	}

	name := req.name()
	args = append(args, name)

	if err := this.Executor.Execute("groupadd", args...); err != nil {
		return failf("cannot create group %s: %w", name, err)
	}

	result, err := LookupGroup(name, this.AllowBadNames)
	if err != nil {
		return failf("cannot lookup group after it was created: %w", err)
	}
	if result == nil {
		return failf("group cannot be found after it was created")
	}

	return result, nil
}

func (this ExecutionBasedEnsurer) modifyGroup(req *GroupRequirement, existing *Group) (*Group, error) {
	fail := func(err error) (*Group, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*Group, error) {
		return fail(fmt.Errorf(message, args...))
	}

	var args []string
	var lookup func() (*Group, error)
	if v := req.Name; len(v) > 0 {
		args = append(args, "-n", strings.Clone(v))
		lookup = func() (*Group, error) {
			return LookupGroup(v, this.AllowBadNames)
		}
	}
	if v := req.Gid; v > 0 {
		args = append(args, "-g", strconv.FormatUint(uint64(v), 10))
		lookup = func() (*Group, error) {
			return LookupGid(v, this.AllowBadNames)
		}
	}
	if lookup == nil {
		panic("neither gid nor name provided")
	}
	args = append(args, existing.Name)

	if err := this.Executor.Execute("groupmod", args...); err != nil {
		return failf("cannot modify group %v: %w", existing, err)
	}

	result, err := lookup()
	if err != nil {
		return failf("cannot lookup group %v after it was modified: %w", existing, err)
	}
	if result == nil {
		return failf("group cannot be found after it was modified")
	}

	return result, nil
}

func (this ExecutionBasedEnsurer) ensureGroups(req GroupRequirements, opts *EnsureOpts) ([]*Group, error) {
	result := make([]*Group, len(req))
	for i, v := range req {
		g, err := this.EnsureGroup(&v, opts)
		if err != nil {
			return nil, fmt.Errorf("%d: %w", i, err)
		}
		result[i] = g
	}
	return result, nil
}
