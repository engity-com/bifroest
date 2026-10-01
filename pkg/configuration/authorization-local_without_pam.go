//go:build unix && (without_pam || (linux && !cgo) || (!linux && !darwin))

package configuration

var (
	defaultAuthorizationLocalPamService = "" //nolint:unused
)

func (this AuthorizationLocal) FeatureFlags() []string {
	return []string{"local"}
}
