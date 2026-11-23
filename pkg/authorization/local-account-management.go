//go:build unix || windows

package authorization

import "github.com/engity-com/bifroest/pkg/errors"

var ErrLocalAccountViewUnavailable = errors.System.Newf("local account view is unavailable")

// localAccountWithManagement overlays a resolved flow-specific observation. A
// nil value means the capability is known not to apply, matching the native
// user view's nil field. Unknown observations must fail before making this view.
type localAccountWithManagement struct {
	account LocalAccountView
	managed *bool
}

func (this localAccountWithManagement) GetField(name string) (any, bool, error) {
	return localAccountFieldWithManagement(name, this.account, this.managed)
}

func localAccountFieldWithManagement(name string, account LocalAccountView, managed *bool) (any, bool, error) {
	if name == "managed" {
		if managed == nil {
			return nil, true, nil
		}
		return *managed, true, nil
	}
	if account == nil {
		return nil, false, ErrLocalAccountViewUnavailable
	}
	return account.GetField(name)
}
