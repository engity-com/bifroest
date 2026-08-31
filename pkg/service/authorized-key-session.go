package service

import (
	"github.com/anmitsu/go-shlex"
	glssh "github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/sys"
)

type authorizedKeySession struct {
	glssh.Session
	command     string
	environment sys.EnvVars
}

func applyAuthorizedKeyPolicy(auth authorization.Authorization, session glssh.Session) (glssh.Session, bool) {
	policy := authorization.AuthorizedKeyPolicyOf(auth)
	if policy == nil {
		return session, false
	}

	environment := sys.EnvVars{}
	environment.Add(session.Environ()...)
	environment.AddAllOf(policy.Environment)
	command := session.RawCommand()
	forced := policy.ForcedCommand != nil
	if forced {
		environment.Set("SSH_ORIGINAL_COMMAND", command)
		command = *policy.ForcedCommand
	}

	return &authorizedKeySession{
		Session:     session,
		command:     command,
		environment: environment,
	}, forced
}

func (this *authorizedKeySession) RawCommand() string {
	return this.command
}

func (this *authorizedKeySession) Command() []string {
	command, _ := shlex.Split(this.command, true)
	return command
}

func (this *authorizedKeySession) Environ() []string {
	return this.environment.Strings()
}
