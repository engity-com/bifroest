package management

import (
	"fmt"

	"github.com/kevinburke/ssh_config"
)

func (target Target) sshSettings() *ssh_config.UserSettings {
	if target.SSHConfigFile == "" {
		return ssh_config.DefaultUserSettings
	}
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return target.SSHConfigFile })
	return settings
}

func (target Target) configurationError(err error) error {
	if target.SSHConfigFile != "" {
		return fmt.Errorf("cannot read selected SSH configuration %q: %w", target.SSHConfigFile, err)
	}
	return fmt.Errorf("cannot read SSH configuration: %w; select a supported, isolated client configuration with --sshConfig <path> (-F)", err)
}
