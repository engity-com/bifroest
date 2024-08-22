//go:build !cgo || !linux || without_pam

package configuration

var (
	defaultAuthorizationLocalPamService = ""
)

func IsPamSupported() bool {
	return false
}
