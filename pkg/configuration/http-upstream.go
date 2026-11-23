package configuration

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// HttpUpstream describes the explicitly trusted ingress, never browser input.
type HttpUpstream struct {
	Mode          string           `yaml:"mode,omitempty"`
	DefaultPrefix string           `yaml:"defaultPrefix,omitempty"`
	DefaultPort   uint16           `yaml:"defaultPort,omitempty"`
	TrustedPeers  HttpTrustedPeers `yaml:"trustedPeers,omitempty"`
}

func (this HttpUpstream) IsReverseProxy() bool { return this.Mode == "reverseProxy" }

func (this *HttpUpstream) SetDefaults() error { *this = HttpUpstream{}; return nil }
func (this *HttpUpstream) Trim() error        { return this.Validate() }

func (this HttpUpstream) Validate() error {
	if this.Mode != "" && this.Mode != "direct" && this.Mode != "reverseProxy" {
		return fmt.Errorf("[mode] must be direct or reverseProxy")
	}
	if err := ValidateHttpPathPrefix(this.DefaultPrefix); err != nil {
		return fmt.Errorf("[defaultPrefix] %w", err)
	}
	if err := this.TrustedPeers.Validate(); err != nil {
		return fmt.Errorf("[trustedPeers] %w", err)
	}
	if this.IsReverseProxy() && len(this.TrustedPeers) == 0 {
		return fmt.Errorf("[trustedPeers] explicitly configure trusted proxy addresses, CIDRs or private")
	}
	if !this.IsReverseProxy() && (len(this.TrustedPeers) != 0 || this.DefaultPrefix != "") {
		return fmt.Errorf("proxy peers and prefix require mode reverseProxy")
	}
	return nil
}

func (this *HttpUpstream) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *HttpUpstream, node *yaml.Node) error {
		type raw HttpUpstream
		return decodeHttpFields(node, (*raw)(target), map[string]string{"mode": "!!str", "defaultPrefix": "!!str", "defaultPort": "!!int", "trustedPeers": "!!seq/!!str"})
	})
}

func (this HttpUpstream) IsEqualTo(other HttpUpstream) bool {
	mode := func(v string) string {
		if v == "" {
			return "direct"
		}
		return v
	}
	return mode(this.Mode) == mode(other.Mode) && this.DefaultPrefix == other.DefaultPrefix && this.DefaultPort == other.DefaultPort && slices.Equal(this.TrustedPeers, other.TrustedPeers)
}

// ValidateHttpPathPrefix accepts an empty root or a canonical, unescaped mount
// path without a trailing slash. Origins and URL paths remain separate values.
func ValidateHttpPathPrefix(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 1024 || !strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return fmt.Errorf("must be empty or an absolute path without a trailing slash")
	}
	for _, part := range strings.Split(value[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("invalid path segment")
		}
		for _, c := range part {
			allowed := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)
			if !allowed {
				return fmt.Errorf("path segments must use unescaped ASCII URL characters")
			}
		}
	}
	return nil
}

type HttpTrustedPeers []string

func (this HttpTrustedPeers) Validate() error {
	if len(this) > 128 {
		return fmt.Errorf("too many proxy peer ranges")
	}
	for index, value := range this {
		if value == "private" {
			continue
		}
		if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Zone() == "" {
			continue
		}
		return fmt.Errorf("[%d] must be an IP address, CIDR or private", index)
	}
	return nil
}

func (this HttpTrustedPeers) Contains(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	for _, value := range this {
		if value == "private" && address.IsPrivate() {
			return true
		}
		if peer, err := netip.ParseAddr(value); err == nil && peer.Unmap() == address {
			return true
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}
