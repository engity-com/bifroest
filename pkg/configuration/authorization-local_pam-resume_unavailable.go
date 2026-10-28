//go:build (unix || windows) && (!linux || !cgo || without_pam)

package configuration

const localPamAccountResumeAvailable = false
