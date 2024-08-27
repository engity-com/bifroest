//go:build (!cgo || !linux || without_pam) && unix

package configuration

var (
	defaultAuthorizationLocalPamService = "" //nolint:golint,unused
)

func (this AuthorizationLocal) FeatureFlags() []string {
	return "local"
}
