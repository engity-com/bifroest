//go:build windows

package configuration

import "fmt"

var defaultAuthorizationLocalPamService = ""

func validateAuthorizationLocalPamService(service string) error {
	if service != "" {
		return fmt.Errorf("pamService is not supported on Windows")
	}
	return nil
}

func (AuthorizationLocal) FeatureFlags() []string { return []string{"local"} }
