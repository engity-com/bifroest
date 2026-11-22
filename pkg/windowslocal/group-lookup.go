package windowslocal

import (
	"context"
	"iter"
	"slices"
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
)

var ErrGroupNotModeled = errors.Config.Newf("local group membership was not modeled")

// HasAccountSID is the direct-membership comparison used by native enumeration
// and controlled observations. Account names, nested groups and domain expansion
// are not substitutes for the supplied account SID.
func HasAccountSID(sid string, members iter.Seq[string]) bool {
	for candidate := range members {
		if sid != "" && candidate == sid {
			return true
		}
	}
	return false
}

// LocalGroupFacts is an observed local group and its complete direct member SID
// list. Nil Members is unknown, not an empty group. The fixture adapter validates
// canonical SID syntax and local scope; no native resolver is used here.
type LocalGroupFacts struct {
	Name, SID string
	Members   *[]string
}

type GroupLookupFacts struct {
	Groups      []LocalGroupFacts
	AbsentNames []string
}

// MemoryGroupLookup owns explicit membership observations. A known absent group
// has no direct members, matching the service's native not-mapped handling.
type MemoryGroupLookup struct {
	groups map[string]*LocalGroupFacts
}

func NewMemoryGroupLookup(facts GroupLookupFacts) (*MemoryGroupLookup, error) {
	result := &MemoryGroupLookup{groups: map[string]*LocalGroupFacts{}}
	sids := map[string]bool{}
	for _, group := range facts.Groups {
		if !ValidSAMName(group.Name) || !validAccountFactIdentity(group.SID) || sids[group.SID] {
			return nil, ErrInvalidAccountFacts
		}
		key := strings.ToLower(group.Name)
		if _, found := result.groups[key]; found {
			return nil, ErrInvalidAccountFacts
		}
		sids[group.SID] = true
		copyOfGroup := group
		if group.Members != nil {
			members := slices.Clone(*group.Members)
			seen := map[string]bool{}
			for _, sid := range members {
				if !validAccountFactIdentity(sid) || seen[sid] {
					return nil, ErrInvalidAccountFacts
				}
				seen[sid] = true
			}
			copyOfGroup.Members = &members
		}
		result.groups[key] = &copyOfGroup
	}
	for _, name := range facts.AbsentNames {
		key := strings.ToLower(name)
		if !ValidSAMName(name) {
			return nil, ErrInvalidAccountFacts
		}
		if _, found := result.groups[key]; found {
			return nil, ErrInvalidAccountFacts
		}
		result.groups[key] = nil
	}
	return result, nil
}

func (this *MemoryGroupLookup) IsMember(ctx context.Context, name, sid string) (bool, error) {
	if ctx == nil || this == nil || this.groups == nil {
		return false, ErrAccountLookupUnavailable
	}
	if err := ctx.Err(); err != nil {
		return false, errors.System.Newf("%w", err)
	}
	if !ValidSAMName(name) || !validAccountFactIdentity(sid) {
		return false, ErrInvalidAccountFacts
	}
	group, found := this.groups[strings.ToLower(name)]
	if !found || group != nil && group.Members == nil {
		return false, ErrGroupNotModeled
	}
	if group == nil {
		return false, nil
	}
	return HasAccountSID(sid, slices.Values(*group.Members)), nil
}
