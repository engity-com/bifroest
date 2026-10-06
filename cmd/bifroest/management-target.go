package main

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/engity-com/bifroest/pkg/ssh"
)

// managementTarget is only selected by the first argument, @user@host:port.
// RawHost remains the SSH config alias rather than its eventual HostName.
type managementTarget struct {
	User         string
	RawHost      string
	Port         uint16
	ExplicitPort bool
}

func parseManagementTarget(args []string) (*managementTarget, []string, error) {
	if len(args) == 0 {
		return nil, args, nil
	}
	if strings.HasPrefix(args[0], "@") || supportsRemoteManagementCommand(args[0]) {
		for _, arg := range args[1:] {
			if strings.HasPrefix(arg, "@") {
				return nil, nil, fmt.Errorf("remote target %q must be the first argument to bifroest", arg)
			}
		}
	}
	if !strings.HasPrefix(args[0], "@") {
		return nil, args, nil
	}
	value := strings.TrimPrefix(args[0], "@")
	if value == "" {
		return nil, nil, fmt.Errorf("remote target after @ is required")
	}
	user, address, withUser := strings.Cut(value, "@")
	if !withUser {
		address = user
		user = ""
	} else if user == "" {
		return nil, nil, fmt.Errorf("remote user before @ is empty")
	}
	for _, candidate := range user {
		if unicode.IsSpace(candidate) || unicode.IsControl(candidate) {
			return nil, nil, fmt.Errorf("remote user contains whitespace or control characters")
		}
	}
	if address == "" || strings.HasPrefix(address, "-") || strings.Contains(address, "@") {
		return nil, nil, fmt.Errorf("invalid remote host %q", address)
	}
	parsed, err := ssh.ParseAddress(address)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid remote target: %w", err)
	}
	host := parsed.Host.String()
	explicitPort := strings.HasPrefix(address, "[") && strings.Contains(address, "]:") ||
		strings.Count(address, ":") == 1 && !isIPv6Literal(address)
	return &managementTarget{User: user, RawHost: host, Port: parsed.Port, ExplicitPort: explicitPort}, args[1:], nil
}

func isIPv6Literal(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.Is6()
}

func supportsRemoteManagementCommand(command string) bool {
	root, _, _ := strings.Cut(command, " ")
	switch root {
	case "session", "flow", "auditlog", "recording", "audit":
		return true
	default:
		return false
	}
}
