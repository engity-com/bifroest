//go:build unix && (!cgo || without_pam || (!linux && !darwin))

package configuration

var (
	defaultAuthorizationLocalPamService = "" //nolint:unused
)

func (this AuthorizationLocal) FeatureFlags() []string {
	return []string{"local"}
}
