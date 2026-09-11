package ssh

import (
	"fmt"
	gonet "net"
	"strings"

	bnet "github.com/engity-com/bifroest/pkg/net"
)

const DefaultPort uint16 = 22

func ParseAddress(value string) (bnet.HostPort, error) {
	value = strings.TrimSpace(value)
	var explicit bnet.HostPort
	explicitErr := explicit.Set(value)
	if explicitErr == nil && !explicit.IsZero() {
		if err := explicit.Validate(); err == nil {
			hostValue := explicit.Host.String()
			if gonet.ParseIP(hostValue) == nil && isUnsafeKnownHostName(hostValue) {
				return bnet.HostPort{}, fmt.Errorf("illegal SSH address %q: host contains unsafe characters", value)
			}
			return explicit, nil
		} else {
			explicitErr = err
		}
	}

	hostValue := value
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
			return bnet.HostPort{}, fmt.Errorf("illegal SSH address %q: invalid brackets", value)
		}
		hostValue = value[1 : len(value)-1]
		if gonet.ParseIP(hostValue) == nil {
			return bnet.HostPort{}, fmt.Errorf("illegal SSH address %q: brackets require an IPv6 address", value)
		}
	} else if strings.Contains(value, ":") && gonet.ParseIP(value) == nil {
		return bnet.HostPort{}, fmt.Errorf("illegal SSH address %q: %w", value, explicitErr)
	}
	if hostValue == "" {
		return bnet.HostPort{}, fmt.Errorf("illegal SSH address %q: host is empty", value)
	}
	if gonet.ParseIP(hostValue) == nil && isUnsafeKnownHostName(hostValue) {
		return bnet.HostPort{}, fmt.Errorf("illegal SSH address %q: host contains unsafe characters", value)
	}
	host, err := bnet.NewHost(hostValue)
	if err != nil {
		return bnet.HostPort{}, fmt.Errorf("illegal SSH address %q: %w", value, err)
	}
	result, err := host.WithPort(DefaultPort)
	if err != nil {
		return bnet.HostPort{}, fmt.Errorf("illegal SSH address %q: %w", value, err)
	}
	return result, nil
}

func isUnsafeKnownHostName(value string) bool {
	if strings.ContainsAny(value, ",*!?[]|#") {
		return true
	}
	for _, candidate := range value {
		if candidate <= ' ' || candidate == 0x7f {
			return true
		}
	}
	return false
}
