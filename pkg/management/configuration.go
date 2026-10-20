package management

import (
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"

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

func (target Target) sshConfigurationFiles() []string {
	if target.SSHConfigFile != "" {
		return []string{target.SSHConfigFile}
	}
	// Match ssh_config's default finders. In particular, its user configuration
	// uses os/user.Current rather than os.UserHomeDir's environment override.
	home := os.Getenv("HOME")
	if current, err := osuser.Current(); err == nil {
		home = current.HomeDir
	}
	return []string{filepath.Join(home, ".ssh", "config"), filepath.Join("/", "etc", "ssh", "ssh_config")}
}

func (target Target) configurationError(err error) error {
	if target.SSHConfigFile != "" {
		return fmt.Errorf("cannot read selected SSH configuration %q: %w", target.SSHConfigFile, err)
	}
	return fmt.Errorf("cannot read SSH configuration: %w; select a supported, isolated client configuration with --sshConfig <path> (-F)", err)
}
