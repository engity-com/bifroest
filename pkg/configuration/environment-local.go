package configuration

import "github.com/engity-com/bifroest/pkg/template"

var (
	DefaultEnvironmentLocalLoginAllowed          = template.BoolOf(true)
	DefaultEnvironmentLocalBanner                = template.MustNewString("")
	DefaultEnvironmentLocalPortForwardingAllowed = template.BoolOf(true)

	_ = RegisterEnvironmentV(func() EnvironmentV {
		return &EnvironmentLocal{}
	})
)
