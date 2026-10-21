package common

type SSHConfigOpts struct {
	SSHConfig string `flag:"sshConfig" short:"F" profile:"remote" placeholder:"<path>" description:"Read only this SSH client configuration instead of the user and system configuration."`
}
