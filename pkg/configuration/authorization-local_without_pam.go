//go:build (!cgo || !linux || without_pam) && unix

package configuration

var (
	defaultAuthorizationLocalPamService = "" //nolint:unused
)

func (this AuthorizationLocal) FeatureFlags() []string {
	return []string{"local"}
}
