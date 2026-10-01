//go:build unix && !darwin

package environment

import "github.com/engity-com/bifroest/pkg/configuration"

func newLocalManagementPolicyTestConfiguration() *configuration.EnvironmentLocal {
	return &configuration.EnvironmentLocal{}
}

func allowUidZeroForLocalManagementTest(*configuration.EnvironmentLocal) {}
