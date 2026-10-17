package common

import "github.com/engity-com/bifroest/pkg/configuration"

// ExecutableConfigurationOpts is available only in the local executable CLI.
// Management and remote invocations select their own profiles, so neither can
// submit a local configuration path to the server.
type ExecutableConfigurationOpts struct {
	Configuration *configuration.Configuration `flag:"configuration" short:"c" profile:"executable" description:"Configuration which should be used."`
}

func (this ExecutableConfigurationOpts) GetConfiguration() *configuration.Configuration {
	return this.Configuration
}
