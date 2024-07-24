//go:build moo && unix && !android

package user

import (
	"bytes"
	"fmt"
	"strconv"
)

func (this EtcUnixEnsurer) EnsureGroup(req *GroupRequirement, opts *EnsureOpts) (*Group, error) {
	if req == nil {
		return nil, fmt.Errorf("nil group requirement")
	}
	_opts := opts.OrDefaults()
	fail := func(err error) (*Group, error) {
		return nil, fmt.Errorf("cannot ensure group %v: %w", req, err)
	}

	groupHandled := false
	highestGroupId := 1000
	if err := modifyEtcGroupOfFile(this.GroupFile, this.AllowBadNames, func(pv *etcGroupEntry, err error) (codecHandlerResult, error) {
		pe := pv.toGroup()
		if req.DoesFulfil(pe) {
			return codecHandlerResultContinue, nil
		}
		if !*_opts.ModifyAllowed {
			return codecHandlerResultContinue, nil
		}

		if err := this.patchEtcGroupEntry(req, pv); err != nil {
			return 0, err
		}

		groupHandled = true
		return codecHandlerResultContinue, nil
	}, func(allowBadName bool) (*etcGroupEntry, error) {
		if !groupHandled && *_opts.CreateAllowed {
			groupHandled = true
			var pv etcGroupEntry
			if err := this.patchEtcGroupEntry(req, &pv); err != nil {
				return nil, err
			}
			return &pv, nil
		}
		return nil, nil
	}); err != nil {
		return fail(err)
	}

	Loo

	return result, nil
}

func (this EtcUnixEnsurer) createGroup(req *GroupRequirement) (*Group, error) {
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

	result, err := LookupGroup(name, this.AllowBadNames, this.SkipIllegalEntries)
	if err != nil {
		return failf("cannot lookup group after it was created: %w", err)
	}
	if result == nil {
		return failf("group cannot be found after it was created")
	}

	return result, nil
}

func (this EtcUnixEnsurer) patchEtcGroupEntry(req *GroupRequirement, existing *etcGroupEntry) error {

	existing.name = bytes.Clone([]byte(req.name()))
	existing.gid = req.Gid

	return nil
}

func (this EtcUnixEnsurer) ensureGroups(req GroupRequirements, opts *EnsureOpts) ([]*Group, error) {
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
