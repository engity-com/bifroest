//go:build darwin

package environment

import "github.com/engity-com/bifroest/pkg/configuration"

func newLocalManagementPolicyTestConfiguration() *configuration.EnvironmentLocal {
	return &configuration.EnvironmentLocal{
		EnvironmentLocalPlatform: configuration.EnvironmentLocalPlatform{
			TargetAccountPolicy: configuration.EnvironmentLocalTargetAccountPolicy{AllowNonLoginShell: true},
		},
	}
}

func allowUidZeroForLocalManagementTest(conf *configuration.EnvironmentLocal) {
	conf.TargetAccountPolicy.AllowUidZero = true
}
