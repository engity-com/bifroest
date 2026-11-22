package windowslocal

import (
	"slices"

	"github.com/engity-com/bifroest/pkg/errors"
)

// accountField shares the template vocabulary of observed password accounts
// and explicitly supplied account facts. Sources are called only for the
// requested metadata; this function never performs native account operations.
func accountField(name string, identity Account, text func(string) (string, error), groups func() ([]group, error)) (any, bool, error) {
	switch name {
	case "name":
		return identity.Name, true, nil
	case "uid":
		return identity.SID, true, nil
	case "managed":
		// Management is a flow-specific policy fact, not an account property.
		return nil, true, nil
	case "displayName", "homeDir", "shell":
		value, err := text(name)
		if err != nil {
			return nil, false, err
		}
		return value, true, nil
	case "groups", "gids":
		values, err := groups()
		if err != nil {
			return nil, false, err
		}
		if name == "groups" {
			return slices.Clone(values), true, nil
		}
		ids := make([]string, len(values))
		for i, value := range values {
			ids[i] = value.SID
		}
		return ids, true, nil
	default:
		return nil, false, errors.Config.Newf("unknown user field %q", name)
	}
}
