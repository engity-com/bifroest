package environment

import (
	"strings"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	bfssh "github.com/engity-com/bifroest/pkg/ssh"
)

func (this *SshRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	projection, err := ProjectSshTarget(ctx, this.conf)
	if err != nil {
		return "", err
	}
	return projection.SessionTarget()
}

// ProjectSshTarget shares the production session-target field evaluation and
// execution's address/account parser without constructing a repository. It does
// not evaluate identity files, certificates, known hosts, loginAllowed, banners,
// connect timeouts or subsystem rules, which belong to other policy/runtime
// stages. Template functions and context getters remain caller dependencies.
func ProjectSshTarget(ctx Context, conf *configuration.EnvironmentSsh) (TargetProjection, error) {
	if conf == nil {
		return TargetProjection{}, errors.Config.Newf("SSH target configuration is unavailable")
	}
	fields := newTargetProjectionFields(ctx)
	fields.string("address", &conf.Address)
	fields.string("user", &conf.User)
	fields.boolean("portForwardingAllowed", &conf.PortForwardingAllowed)
	fields.boolean("reversePortForwardingAllowed", &conf.ReversePortForwardingAllowed)
	if fields.err != nil {
		return TargetProjection{}, fields.err
	}
	address, user, err := resolveSshTarget(fields.values["address"], fields.values["user"])
	if err != nil {
		return TargetProjection{}, sessionTargetError(errors.Config, err, "cannot resolve SSH session target address or account")
	}
	// DNS is case-insensitive, but keep the final dot: an absolute DNS name
	// must not be conflated with a relative name subject to search domains.
	address.Host.Dns = strings.ToLower(address.Host.Dns)
	fields.values["address"] = address.String()
	fields.values["user"] = user
	return fields.projection("ssh")
}

func resolveSshTarget(rawAddress, rawUser string) (net.HostPort, string, error) {
	address, err := bfssh.ParseAddress(rawAddress)
	if err != nil {
		return net.HostPort{}, "", errors.Config.Newf("illegal rendered SSH target address: %w", err)
	}
	user := strings.TrimSpace(rawUser)
	if user == "" {
		return net.HostPort{}, "", errors.Config.Newf("rendered SSH target user is empty")
	}
	return address, user, nil
}
