//go:build !without_pam && (darwin || (linux && cgo))

package configuration

var (
	defaultAuthorizationLocalPamService = "sshd"
)

func (this AuthorizationLocal) FeatureFlags() []string {
	return []string{"local[pam]"}
}
