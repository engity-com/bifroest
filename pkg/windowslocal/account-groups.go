package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// A transient, request-local comparison value, never a persisted rights cache.
// The native reader retains the existing direct local/BUILTIN alias contract;
// this does not add nested or domain-group membership semantics.
func inspectSAMGroupsFlow(ctx context.Context, identity func() error, read func() ([]group, error)) (result []group, resultErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("missing native SAM group context")
	}
	defer func() {
		resultErr = errors.Join(resultErr, ctx.Err())
		if resultErr != nil {
			result = nil
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if identity == nil || read == nil {
		return nil, fmt.Errorf("incomplete native SAM group operations")
	}
	if err := identity(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	groups, err := read()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result = slices.Clone(groups)
	names, ids := map[string]bool{}, map[string]bool{}
	for _, value := range result {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := strings.ToLower(value.Name)
		if value.Name == "" || value.SID == "" || names[name] || ids[value.SID] {
			return nil, fmt.Errorf("incomplete or ambiguous native SAM group identity")
		}
		names[name], ids[value.SID] = true, true
	}
	slices.SortFunc(result, func(a, b group) int {
		if compared := strings.Compare(a.SID, b.SID); compared != 0 {
			return compared
		}
		return strings.Compare(a.Name, b.Name)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := identity(); err != nil {
		return nil, err
	}
	return result, nil
}

func sameSAMGroups(a, b []group) bool { return slices.Equal(a, b) }
