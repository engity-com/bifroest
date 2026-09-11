package service

import (
	"github.com/anmitsu/go-shlex"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/sys"
)

type authorizedKeySession struct {
	essh.Session
	command                  string
	originalCommand          string
	hasOriginalCommand       bool
	environment              sys.EnvVars
	clientEnvironment        []string
	authorizedKeyEnvironment sys.EnvVars
}

func applyAuthorizedKeyPolicy(auth authorization.Authorization, session essh.Session) (essh.Session, bool) {
	policy := authorization.AuthorizedKeyPolicyOf(auth)
	if policy == nil {
		return session, false
	}

	environment := sys.EnvVars{}
	environment.Add(session.Environ()...)
	environment.AddAllOf(policy.Environment)
	authorizedKeyEnvironment := policy.Environment.Clone()
	originalCommand := session.RawCommand()
	command := originalCommand
	forced := policy.ForcedCommand != nil
	if forced {
		environment.Set("SSH_ORIGINAL_COMMAND", command)
		authorizedKeyEnvironment.Set("SSH_ORIGINAL_COMMAND", command)
		command = *policy.ForcedCommand
	}

	return &authorizedKeySession{
		Session:                  session,
		command:                  command,
		originalCommand:          originalCommand,
		hasOriginalCommand:       forced,
		environment:              environment,
		clientEnvironment:        session.Environ(),
		authorizedKeyEnvironment: authorizedKeyEnvironment,
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

func (this *authorizedKeySession) ClientEnvironment() []string {
	return append([]string(nil), this.clientEnvironment...)
}

func (this *authorizedKeySession) AuthorizedKeyEnvironment() sys.EnvVars {
	return this.authorizedKeyEnvironment.Clone()
}

func (this *authorizedKeySession) OriginalCommand() (string, bool) {
	return this.originalCommand, this.hasOriginalCommand
}
