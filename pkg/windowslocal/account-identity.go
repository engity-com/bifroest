package windowslocal

// Account identifies a local SAM user. Callers must retain both fields when
// passing an account to native authentication or account-policy checks.
type Account struct {
	Name string
	SID  string
}
