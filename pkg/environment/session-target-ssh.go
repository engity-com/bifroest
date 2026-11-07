package environment

import (
	"fmt"
	"strings"

	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	bfssh "github.com/engity-com/bifroest/pkg/ssh"
)

func (this *SshRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	fields := newTargetFields(ctx)
	fields.string("address", &this.conf.Address)
	fields.string("user", &this.conf.User)
	fields.boolean("portForwardingAllowed", &this.conf.PortForwardingAllowed)
	fields.boolean("reversePortForwardingAllowed", &this.conf.ReversePortForwardingAllowed)
	if fields.err != nil {
		return "", fields.err
	}
	address, user, err := resolveSshTarget(fields.values["address"], fields.values["user"])
	if err != nil {
		return "", fmt.Errorf("cannot resolve SSH session target address or account")
	}
	// DNS is case-insensitive, but keep the final dot: an absolute DNS name
	// must not be conflated with a relative name subject to search domains.
	address.Host.Dns = strings.ToLower(address.Host.Dns)
	fields.values["address"] = address.String()
	fields.values["user"] = user
	return fields.target("ssh")
}

func resolveSshTarget(rawAddress, rawUser string) (net.HostPort, string, error) {
	address, err := bfssh.ParseAddress(rawAddress)
	if err != nil {
		return net.HostPort{}, "", fmt.Errorf("illegal rendered SSH target address: %w", err)
	}
	user := strings.TrimSpace(rawUser)
	if user == "" {
		return net.HostPort{}, "", fmt.Errorf("rendered SSH target user is empty")
	}
	return address, user, nil
}
