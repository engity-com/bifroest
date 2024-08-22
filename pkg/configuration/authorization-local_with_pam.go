//go:build cgo && linux && !without_pam

package configuration

var (
	defaultAuthorizationLocalPamService = "sshd"
)

func IsPamSupported() bool {
	return true
}
