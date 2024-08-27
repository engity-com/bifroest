//go:build cgo && linux && !without_pam

package configuration

var (
	defaultAuthorizationLocalPamService = "sshd"
)

func (this AuthorizationLocal) FeatureFlags() []string {
	return "local[pam]"
}
