//go:build unix

package user

import (
	"reflect"

	"github.com/engity-com/bifroest/pkg/errors"
)

// GroupFieldView supplies the production group/groups metadata vocabulary.
// Callers own this read capability; the function creates no repository and
// substitutes no host data for unavailable observations.
type GroupFieldView interface {
	GetField(string) (any, bool, error)
}

// IsInGroupByName shares the service's existing managed-group decision. Names
// are compared exactly; numeric GIDs do not participate. The primary group is
// checked first, so a match does not require supplementary group observations.
// Otherwise missing facts are errors, never an inferred negative membership.
func IsInGroupByName(account GroupFieldView, name string) (bool, error) {
	if name == "" || nilGroupFieldView(account) {
		return false, ErrInvalidAccountFacts
	}
	value, present, err := account.GetField("group")
	if err != nil {
		return false, err
	}
	if !present {
		return false, errors.Config.Newf("%w: group", ErrAccountFieldUnavailable)
	}
	primary, ok := value.(Group)
	if !ok {
		return false, ErrInvalidAccountFacts
	}
	if primary.Name == name {
		return true, nil
	}
	value, present, err = account.GetField("groups")
	if err != nil {
		return false, err
	}
	if !present {
		return false, errors.Config.Newf("%w: groups", ErrAccountFieldUnavailable)
	}
	groups, ok := value.(Groups)
	if !ok {
		return false, ErrInvalidAccountFacts
	}
	for _, group := range groups {
		if group.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func nilGroupFieldView(value GroupFieldView) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
