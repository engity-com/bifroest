//go:build !cgo || !linux || without_pam

package configuration

var (
	defaultAuthorizationLocalPamService = "" //nolint:golint,unused
)

func IsPamSupported() bool {
	return false
}
