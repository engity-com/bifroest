package common

import "github.com/engity-com/bifroest/pkg/configuration"

// ExecutableConfigurationOpts is available only in the local executable CLI.
// The management application selects only ProfileManagement, so a client
// cannot submit a local configuration path to the server.
type ExecutableConfigurationOpts struct {
	Configuration *configuration.Configuration `flag:"configuration" short:"c" profile:"executable" description:"Configuration which should be used."`
}

func (this ExecutableConfigurationOpts) GetConfiguration() *configuration.Configuration {
	return this.Configuration
}
