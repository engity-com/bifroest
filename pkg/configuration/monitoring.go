package configuration

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
)

var DefaultMonitoringAddresses = net.NetAddresses{net.MustNewAddress("localhost:9090")}

// Monitoring is independent of browser access and has no certificate automation.
type Monitoring struct {
	Enabled                 bool                  `yaml:"enabled,omitempty"`
	Addresses               net.NetAddresses      `yaml:"addresses"`
	AllowedRemoteHosts      MonitoringRemoteHosts `yaml:"allowedRemoteHosts,omitempty"`
	BearerToken             string                `yaml:"bearerToken,omitempty" sensitive:"true"`
	BearerTokenFile         string                `yaml:"bearerTokenFile,omitempty" sensitive:"true"`
	Tls                     MonitoringTls         `yaml:"tls,omitempty"`
	ReadHeaderTimeout       common.Duration       `yaml:"readHeaderTimeout,omitempty"`
	IdleTimeout             common.Duration       `yaml:"idleTimeout,omitempty"`
	GracefulShutdownTimeout common.Duration       `yaml:"gracefulShutdownTimeout,omitempty"`
	MaxHeaderBytes          uint32                `yaml:"maxHeaderBytes,omitempty"`
}

func (this *Monitoring) IsEnabled() bool { return this != nil && this.Enabled }

func (this *Monitoring) SetDefaults() error {
	*this = Monitoring{
		Addresses: slices.Clone(DefaultMonitoringAddresses), ReadHeaderTimeout: DefaultHttpReadHeaderTimeout,
		IdleTimeout: DefaultHttpIdleTimeout, GracefulShutdownTimeout: DefaultHttpGracefulShutdownTimeout,
		MaxHeaderBytes: DefaultHttpMaxHeaderBytes,
	}
	return nil
}

func (this *Monitoring) Trim() error {
	if this == nil {
		return nil
	}
	this.BearerTokenFile = strings.TrimSpace(this.BearerTokenFile)
	if err := this.AllowedRemoteHosts.Trim(); err != nil {
		return configurationFieldError(this, "allowedRemoteHosts", err)
	}
	if err := this.Tls.Trim(); err != nil {
		return configurationFieldError(this, "tls", err)
	}
	return this.Validate()
}

func (this *Monitoring) Validate() error {
	if this == nil {
		return nil
	}
	// Reuse listener address and request-budget validation, not HTTPS domain or ACME requirements.
	http := Http{Addresses: this.Addresses, ReadHeaderTimeout: this.ReadHeaderTimeout,
		StartupTimeout: DefaultHttpStartupTimeout, IdleTimeout: this.IdleTimeout,
		GracefulShutdownTimeout: this.GracefulShutdownTimeout, MaxHeaderBytes: this.MaxHeaderBytes,
		RememberMe: HttpRememberMe{IdleTimeout: DefaultHttpRememberMeIdleTimeout}}
	if err := http.Validate(); err != nil {
		return err
	}
	if this.Enabled && len(this.Addresses) == 0 {
		return fmt.Errorf("[addresses] at least one listener address is required")
	}
	if this.BearerToken != "" && this.BearerTokenFile != "" {
		return fmt.Errorf("[bearerToken] cannot be combined with bearerTokenFile")
	}
	if this.BearerToken != "" && !ValidMonitoringBearerToken(this.BearerToken) {
		return fmt.Errorf("[bearerToken] must be a nonempty RFC 6750 token of at most 4096 bytes")
	}
	if err := validateHttpFilePath(this.BearerTokenFile, true); err != nil {
		return configurationFieldError(this, "bearerTokenFile", err)
	}
	if err := this.AllowedRemoteHosts.Validate(); err != nil {
		return configurationFieldError(this, "allowedRemoteHosts", err)
	}
	if err := this.Tls.Validate(); err != nil {
		return configurationFieldError(this, "tls", err)
	}
	return nil
}

func ValidMonitoringBearerToken(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	padding := false
	for _, ch := range value {
		if ch == '=' {
			padding = true
			continue
		}
		allowed := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("-._~+/", ch)
		if padding || !allowed {
			return false
		}
	}
	return value[0] != '='
}

func (this *Monitoring) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Monitoring, node *yaml.Node) error {
		fields, err := effectiveHttpFields(node)
		if err != nil {
			return err
		}
		if err := rejectUnknownConfigurationFields(node, target); err != nil {
			return err
		}
		var hosts MonitoringRemoteHosts
		if value, ok := fields["allowedRemoteHosts"]; ok {
			if err := value.Decode(&hosts); err != nil {
				return err
			}
		}
		type raw Monitoring
		// Rebuild the effective mapping without the deliberately nullable peer list.
		filtered := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for name, value := range fields {
			if name == "allowedRemoteHosts" {
				continue
			}
			filtered.Content = append(filtered.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, &value)
		}
		if err := decodeHttpFields(filtered, (*raw)(target), map[string]string{"enabled": "!!bool", "addresses": "!!seq/!!str", "bearerToken": "!!str", "bearerTokenFile": "!!str", "tls": "!!map", "readHeaderTimeout": "!!str", "idleTimeout": "!!str", "gracefulShutdownTimeout": "!!str", "maxHeaderBytes": "!!int"}); err != nil {
			return err
		}
		target.AllowedRemoteHosts = hosts
		return nil
	})
}

func (this *Monitoring) IsEqualTo(value any) bool {
	var other *Monitoring
	switch value := value.(type) {
	case Monitoring:
		other = &value
	case *Monitoring:
		other = value
	default:
		return false
	}
	if this == nil || other == nil {
		return this == other
	}
	// Hostname resolution may yield a four-byte IPv4 address, while parsing its
	// serialized literal yields a mapped representation of that same endpoint.
	addressesEqual := slices.EqualFunc(this.Addresses, other.Addresses, func(left, right net.Address) bool { return left.String() == right.String() })
	return this.Enabled == other.Enabled && addressesEqual && slices.Equal(this.AllowedRemoteHosts, other.AllowedRemoteHosts) &&
		this.BearerToken == other.BearerToken && this.BearerTokenFile == other.BearerTokenFile && this.Tls.IsEqualTo(other.Tls) &&
		this.ReadHeaderTimeout == other.ReadHeaderTimeout && this.IdleTimeout == other.IdleTimeout && this.GracefulShutdownTimeout == other.GracefulShutdownTimeout && this.MaxHeaderBytes == other.MaxHeaderBytes
}

type MonitoringTls struct {
	Enabled      bool              `yaml:"enabled,omitempty"`
	Certificates []HttpCertificate `yaml:"certificates,omitempty"`
}

func (this *MonitoringTls) SetDefaults() error { *this = MonitoringTls{}; return nil }
func (this *MonitoringTls) Trim() error {
	for index := range this.Certificates {
		if err := this.Certificates[index].Trim(); err != nil {
			return fmt.Errorf("[certificates][%d] %w", index, err)
		}
	}
	return this.Validate()
}
func (this *MonitoringTls) Validate() error {
	if !this.Enabled && len(this.Certificates) > 0 {
		return fmt.Errorf("[enabled] must be true when certificates are configured")
	}
	if this.Enabled && len(this.Certificates) == 0 {
		return fmt.Errorf("[certificates] required when TLS is enabled")
	}
	for index := range this.Certificates {
		if err := this.Certificates[index].Validate(); err != nil {
			return fmt.Errorf("[certificates][%d] %w", index, err)
		}
	}
	return nil
}
func (this *MonitoringTls) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *MonitoringTls, node *yaml.Node) error {
		type raw MonitoringTls
		return decodeHttpFields(node, (*raw)(target), map[string]string{"enabled": "!!bool", "certificates": "!!seq/!!map"})
	})
}
func (this MonitoringTls) IsEqualTo(other MonitoringTls) bool {
	return this.Enabled == other.Enabled && slices.Equal(this.Certificates, other.Certificates)
}

type MonitoringRemoteHosts []string

func (this *MonitoringRemoteHosts) Trim() error {
	var values MonitoringRemoteHosts
	for _, value := range *this {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	*this = values
	return this.Validate()
}
func (this MonitoringRemoteHosts) Validate() error {
	for index, value := range this {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, err := netip.ParsePrefix(value); err == nil {
			continue
		}
		if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
			continue
		}
		return fmt.Errorf("[%d] must be an IPv4/IPv6 address or CIDR network", index)
	}
	return nil
}
func (this *MonitoringRemoteHosts) UnmarshalYAML(node *yaml.Node) error {
	if node.Tag == "!!null" {
		*this = nil
		return nil
	}
	if node.Tag == "!!str" {
		*this = MonitoringRemoteHosts{node.Value}
		return this.Trim()
	}
	if node.Kind != yaml.SequenceNode {
		return reportYamlRelatedErrf(node, "allowedRemoteHosts must be a list of IP addresses or CIDR networks")
	}
	for _, item := range node.Content {
		if item.Kind == yaml.AliasNode {
			item = item.Alias
		}
		if item.Tag != "!!str" && item.Tag != "!!null" {
			return reportYamlRelatedErrf(item, "allowedRemoteHosts entries must be IP addresses or CIDR networks")
		}
	}
	type raw MonitoringRemoteHosts
	if err := node.Decode((*raw)(this)); err != nil {
		return err
	}
	return this.Trim()
}
