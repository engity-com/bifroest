//go:build cgo && (linux || darwin) && !without_pam

package configuration

var (
	defaultAuthorizationLocalPamService = "sshd"
)

func (this AuthorizationLocal) FeatureFlags() []string {
	return []string{"local[pam]"}
}
