package windowslocal

import "errors"

var ErrNotFound = errors.New("local SAM account not found")

// Account identifies a local SAM user. Callers must retain both fields when
// passing an account to native authentication or account-policy checks.
type Account struct {
	Name string
	SID  string
}
