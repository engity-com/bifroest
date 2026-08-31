package authorization

import (
	"fmt"
	gonet "net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

var environmentVariableNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type AuthorizedKeyPolicy struct {
	ForcedCommand          *string
	Environment            sys.EnvVars
	PtyAllowed             bool
	PortForwardingAllowed  bool
	AgentForwardingAllowed bool

	permitOpen   []authorizedKeyHostPortPattern
	permitListen []authorizedKeyHostPortPattern
}

func AuthorizedKeyPolicyOf(auth Authorization) *AuthorizedKeyPolicy {
	if provider, ok := auth.(interface{ AuthorizedKeyPolicy() *AuthorizedKeyPolicy }); ok {
		return provider.AuthorizedKeyPolicy()
	}
	return nil
}

func IsAgentForwardingAllowed(auth Authorization) bool {
	policy := AuthorizedKeyPolicyOf(auth)
	return policy == nil || policy.AgentForwardingAllowed
}

func (this *AuthorizedKeyPolicy) AllowsOpen(dest bnet.HostPort) bool {
	if this == nil {
		return true
	}
	return this.PortForwardingAllowed && matchesAuthorizedKeyHostPortPatterns(this.permitOpen, dest.Host.String(), uint32(dest.Port))
}

func (this *AuthorizedKeyPolicy) AllowsListen(host string, port uint32) bool {
	if this == nil {
		return true
	}
	return this.PortForwardingAllowed && matchesAuthorizedKeyHostPortPatterns(this.permitListen, host, port)
}

func evaluateAuthorizedKeyOptions(options []crypto.AuthorizedKeyOption, remote bnet.Host, now time.Time) (*AuthorizedKeyPolicy, bool, error) {
	if len(options) == 0 {
		return nil, true, nil
	}

	policy := &AuthorizedKeyPolicy{
		PtyAllowed:             true,
		PortForwardingAllowed:  true,
		AgentForwardingAllowed: true,
	}
	var restrict bool
	var ptyAllowed, portForwardingAllowed, agentForwardingAllowed *bool
	var from, expiryTime *string

	setCapability := func(target **bool, value bool, name string) error {
		if *target != nil {
			return fmt.Errorf("authorized key capability %q is configured more than once", name)
		}
		*target = &value
		return nil
	}

	for _, option := range options {
		switch option.Type {
		case crypto.AuthorizedKeyCommand:
			if policy.ForcedCommand != nil {
				return nil, false, fmt.Errorf("authorized key option %q is configured more than once", option.Type)
			}
			value := option.Value
			policy.ForcedCommand = &value
		case crypto.AuthorizedKeyEnvironment:
			name, value, ok := strings.Cut(option.Value, "=")
			if !ok || !environmentVariableNamePattern.MatchString(name) || strings.IndexByte(value, 0) >= 0 {
				return nil, false, fmt.Errorf("illegal authorized key environment value %q", option.Value)
			}
			if _, exists := policy.Environment[name]; exists {
				return nil, false, fmt.Errorf("authorized key environment variable %q is configured more than once", name)
			}
			policy.Environment.Set(name, value)
		case crypto.AuthorizedKeyExpiryTime:
			if expiryTime != nil {
				return nil, false, fmt.Errorf("authorized key option %q is configured more than once", option.Type)
			}
			value := option.Value
			expiryTime = &value
		case crypto.AuthorizedKeyFrom:
			if from != nil {
				return nil, false, fmt.Errorf("authorized key option %q is configured more than once", option.Type)
			}
			value := option.Value
			from = &value
		case crypto.AuthorizedKeyPermitListen:
			pattern, err := parseAuthorizedKeyHostPortPattern(option.Value, true)
			if err != nil {
				return nil, false, err
			}
			policy.permitListen = append(policy.permitListen, pattern)
		case crypto.AuthorizedKeyPermitOpen:
			pattern, err := parseAuthorizedKeyHostPortPattern(option.Value, false)
			if err != nil {
				return nil, false, err
			}
			policy.permitOpen = append(policy.permitOpen, pattern)
		case crypto.AuthorizedKeyPortForwarding:
			if err := setCapability(&portForwardingAllowed, true, option.Type.String()); err != nil {
				return nil, false, err
			}
		case crypto.AuthorizedKeyNoPortForwarding:
			if err := setCapability(&portForwardingAllowed, false, option.Type.String()); err != nil {
				return nil, false, err
			}
		case crypto.AuthorizedKeyPty:
			if err := setCapability(&ptyAllowed, true, option.Type.String()); err != nil {
				return nil, false, err
			}
		case crypto.AuthorizedKeyNoPty:
			if err := setCapability(&ptyAllowed, false, option.Type.String()); err != nil {
				return nil, false, err
			}
		case crypto.AuthorizedKeyAgentForwarding:
			if err := setCapability(&agentForwardingAllowed, true, option.Type.String()); err != nil {
				return nil, false, err
			}
		case crypto.AuthorizedKeyNoAgentForwarding:
			if err := setCapability(&agentForwardingAllowed, false, option.Type.String()); err != nil {
				return nil, false, err
			}
		case crypto.AuthorizedKeyRestrict:
			restrict = true
		default:
			return nil, false, fmt.Errorf("unsupported authorized key option %q", option.Type)
		}
	}

	if restrict {
		policy.PtyAllowed = false
		policy.PortForwardingAllowed = false
		policy.AgentForwardingAllowed = false
	}
	if ptyAllowed != nil {
		policy.PtyAllowed = *ptyAllowed
	}
	if portForwardingAllowed != nil {
		policy.PortForwardingAllowed = *portForwardingAllowed
	}
	if agentForwardingAllowed != nil {
		policy.AgentForwardingAllowed = *agentForwardingAllowed
	}

	if from != nil {
		matches, err := matchesAuthorizedKeySource(*from, remote)
		if err != nil {
			return nil, false, err
		}
		if !matches {
			return nil, false, nil
		}
	}
	if expiryTime != nil {
		expiresAt, err := parseAuthorizedKeyExpiryTime(*expiryTime)
		if err != nil {
			return nil, false, err
		}
		if !now.Before(expiresAt) {
			return nil, false, nil
		}
	}

	return policy, true, nil
}

func parseAuthorizedKeyExpiryTime(value string) (time.Time, error) {
	location := time.Local
	if strings.HasSuffix(value, "Z") {
		location = time.UTC
		value = strings.TrimSuffix(value, "Z")
	}

	layout := map[int]string{
		8:  "20060102",
		12: "200601021504",
		14: "20060102150405",
	}[len(value)]
	if layout == "" {
		return time.Time{}, fmt.Errorf("illegal authorized key expiry time %q", value)
	}
	result, err := time.ParseInLocation(layout, value, location)
	if err != nil {
		return time.Time{}, fmt.Errorf("illegal authorized key expiry time %q: %w", value, err)
	}
	return result, nil
}

func matchesAuthorizedKeySource(value string, remote bnet.Host) (bool, error) {
	target := remote.String()
	ip := gonet.ParseIP(target)
	if ip == nil {
		return false, fmt.Errorf("cannot apply authorized key source restriction to non-IP remote host %q", target)
	}

	matched := false
	for _, plainPattern := range strings.Split(value, ",") {
		plainPattern = strings.TrimSpace(plainPattern)
		negated := strings.HasPrefix(plainPattern, "!")
		pattern := strings.TrimPrefix(plainPattern, "!")
		if pattern == "" {
			return false, fmt.Errorf("illegal empty authorized key source pattern")
		}

		patternMatches, err := matchesAuthorizedKeySourcePattern(pattern, target, ip)
		if err != nil {
			return false, err
		}
		if patternMatches && negated {
			return false, nil
		}
		if patternMatches {
			matched = true
		}
	}
	return matched, nil
}

func matchesAuthorizedKeySourcePattern(pattern, target string, ip gonet.IP) (bool, error) {
	if _, network, err := gonet.ParseCIDR(pattern); err == nil {
		return network.Contains(ip), nil
	}
	if expected := gonet.ParseIP(pattern); expected != nil {
		return expected.Equal(ip), nil
	}
	if strings.ContainsAny(pattern, "*?") && strings.IndexFunc(pattern, func(r rune) bool {
		return !strings.ContainsRune("0123456789abcdefABCDEF:.*?", r)
	}) < 0 {
		matches, err := path.Match(pattern, target)
		if err != nil {
			return false, fmt.Errorf("illegal authorized key source pattern %q: %w", pattern, err)
		}
		return matches, nil
	}
	return false, fmt.Errorf("authorized key source hostname patterns are not supported: %q", pattern)
}

type authorizedKeyHostPortPattern struct {
	host string
	port *uint16
}

func parseAuthorizedKeyHostPortPattern(value string, portOnlyAllowed bool) (authorizedKeyHostPortPattern, error) {
	plainHost := "*"
	plainPort := value
	if !portOnlyAllowed || strings.Contains(value, ":") {
		var err error
		plainHost, plainPort, err = gonet.SplitHostPort(value)
		if err != nil {
			return authorizedKeyHostPortPattern{}, fmt.Errorf("illegal authorized key host/port restriction %q: %w", value, err)
		}
	}
	if plainHost == "" {
		plainHost = "*"
	}

	result := authorizedKeyHostPortPattern{host: strings.ToLower(plainHost)}
	if plainPort != "*" {
		parsed, err := strconv.ParseUint(plainPort, 10, 16)
		if err != nil {
			return authorizedKeyHostPortPattern{}, fmt.Errorf("illegal authorized key port restriction %q: %w", value, err)
		}
		port := uint16(parsed)
		result.port = &port
	}
	return result, nil
}

func matchesAuthorizedKeyHostPortPatterns(patterns []authorizedKeyHostPortPattern, host string, port uint32) bool {
	if len(patterns) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, pattern := range patterns {
		hostMatches, err := path.Match(pattern.host, host)
		if err == nil && hostMatches && (pattern.port == nil || port == uint32(*pattern.port)) {
			return true
		}
	}
	return false
}
