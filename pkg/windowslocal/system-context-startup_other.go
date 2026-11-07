//go:build !windows && !linux

package windowslocal

// Windows supplies the native checker. Other platforms use this package only
// for the portable control-flow models, not native System-context operations.
func s4uOnStartupThread() (bool, error) { return false, nil }
