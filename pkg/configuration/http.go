package configuration

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
)

var (
	DefaultHttpAddresses               = net.NetAddresses{net.MustNewAddress(":443")}
	DefaultHttpStartupTimeout          = common.DurationOf(2 * time.Minute)
	DefaultHttpReadHeaderTimeout       = common.DurationOf(10 * time.Second)
	DefaultHttpIdleTimeout             = common.DurationOf(time.Minute)
	DefaultHttpGracefulShutdownTimeout = common.DurationOf(30 * time.Second)
	DefaultHttpRememberMeIdleTimeout   = common.DurationOf(6 * time.Hour)
)

const DefaultHttpMaxHeaderBytes = uint32(1 << 20)

// Http is optional at the root. Neither omission nor an explicit disabled block
// starts a listener, reads certificates or initiates ACME requests.
type Http struct {
	Enabled                 HttpMode         `yaml:"enabled,omitempty"`
	WebUi                   HttpComponent    `yaml:"webUi,omitempty"`
	SshTunnel               HttpComponent    `yaml:"sshTunnel,omitempty"`
	LoginFlow               HttpComponent    `yaml:"loginFlow,omitempty"`
	Addresses               net.NetAddresses `yaml:"addresses"`
	Domains                 HttpDomains      `yaml:"domains,omitempty"`
	Tls                     *Tls             `yaml:"tls,omitempty"`
	tlsExplicitNull         bool
	Upstream                HttpUpstream    `yaml:"upstream,omitempty"`
	StartupTimeout          common.Duration `yaml:"startupTimeout,omitempty"`
	ReadHeaderTimeout       common.Duration `yaml:"readHeaderTimeout,omitempty"`
	IdleTimeout             common.Duration `yaml:"idleTimeout,omitempty"`
	GracefulShutdownTimeout common.Duration `yaml:"gracefulShutdownTimeout"`
	MaxHeaderBytes          uint32          `yaml:"maxHeaderBytes,omitempty"`
	RememberMe              HttpRememberMe  `yaml:"rememberMe,omitempty"`
	AssetsDirectory         string          `yaml:"assetsDirectory,omitempty"`
	CustomCss               HttpAssetFiles  `yaml:"customCss,omitempty"`
	CustomJs                HttpAssetFiles  `yaml:"customJs,omitempty"`
	CustomHtmlHead          string          `yaml:"customHtmlHead,omitempty"`
	CustomHtmlBody          string          `yaml:"customHtmlBody,omitempty"`
}

// IsEnabled selects application HTTP, not the validation-only TLS listener.
func (this *Http) IsEnabled() bool { return this != nil && this.Enabled == HttpEnabled }
func (this *Http) IsListenerEnabled() bool {
	return this != nil && (this.Enabled == HttpEnabled || this.Enabled == HttpAcmeTlsAlpnOnly)
}
func (this *Http) IsAcmeTlsAlpnOnly() bool {
	return this != nil && this.Enabled == HttpAcmeTlsAlpnOnly
}

func (this *Http) SetDefaults() error {
	*this = Http{
		Addresses: slices.Clone(DefaultHttpAddresses), StartupTimeout: DefaultHttpStartupTimeout,
		ReadHeaderTimeout: DefaultHttpReadHeaderTimeout, IdleTimeout: DefaultHttpIdleTimeout,
		GracefulShutdownTimeout: DefaultHttpGracefulShutdownTimeout, MaxHeaderBytes: DefaultHttpMaxHeaderBytes,
		RememberMe: HttpRememberMe{IdleTimeout: DefaultHttpRememberMeIdleTimeout},
	}
	return nil
}

func (this *Http) Trim() error {
	return this.trim(true)
}

func (this *Http) trim(requireResolvedTLS bool) error {
	if this == nil {
		return nil
	}
	this.AssetsDirectory = strings.TrimSpace(this.AssetsDirectory)
	if err := this.Domains.Trim(); err != nil {
		return configurationFieldError(this, "domains", err)
	}
	if err := this.Tls.Trim(); err != nil {
		return configurationFieldError(this, "tls", err)
	}
	return this.validate(requireResolvedTLS)
}

func (this *Http) Validate() error {
	return this.validate(true)
}

func (this *Http) validate(requireResolvedTLS bool) error {
	if this == nil {
		return nil
	}
	if err := this.Enabled.Validate(); err != nil {
		return configurationFieldError(this, "enabled", err)
	}
	if this.IsListenerEnabled() && len(this.Addresses) == 0 {
		return fmt.Errorf("[addresses] at least one listener address is required")
	}
	seenAddresses := make(map[string]struct{}, len(this.Addresses))
	for index, address := range this.Addresses {
		if address.IsZero() {
			return fmt.Errorf("[addresses][%d] must not be empty", index)
		}
		// Address.String does not include the tcp4/tcp6 network prefix. An exact
		// duplicate would still make the jointly critical listener startup fail.
		if _, exists := seenAddresses[address.String()]; exists {
			return fmt.Errorf("[addresses][%d] duplicates a listener address", index)
		}
		seenAddresses[address.String()] = struct{}{}
	}
	if err := this.Domains.Validate(); err != nil {
		return configurationFieldError(this, "domains", err)
	}
	if this.IsListenerEnabled() && len(this.Domains) == 0 {
		return fmt.Errorf("[domains] at least one explicit domain is required")
	}
	if err := this.Tls.Validate(); err != nil {
		return configurationFieldError(this, "tls", err)
	}
	if err := this.Upstream.Validate(); err != nil {
		return configurationFieldError(this, "upstream", err)
	}
	tlsPending := !requireResolvedTLS && (this.Tls == nil && !this.tlsExplicitNull || this.Tls != nil && this.Tls.implicit)
	if this.IsAcmeTlsAlpnOnly() {
		if !tlsPending && !this.Tls.IsEnabled() || this.Upstream.IsReverseProxy() {
			return fmt.Errorf("[enabled] acmeTlsAlpnOnly requires TLS and direct upstream mode")
		}
		// Inline decoding precedes root reference resolution.
		if !tlsPending && (this.Tls.Reference == "" || this.Tls.definition != nil) {
			definition, err := this.Tls.ServerDefinition()
			if err != nil {
				return err
			}
			if !definition.Acme.IsEnabled() {
				return fmt.Errorf("[tls][acme] required for acmeTlsAlpnOnly")
			}
		}
	}
	if !tlsPending && this.IsEnabled() && !this.Tls.IsEnabled() && !this.Upstream.IsReverseProxy() {
		return fmt.Errorf("[tls] required unless upstream.mode is reverseProxy")
	}
	for _, field := range []struct {
		name  string
		value common.Duration
	}{
		{"startupTimeout", this.StartupTimeout}, {"readHeaderTimeout", this.ReadHeaderTimeout}, {"idleTimeout", this.IdleTimeout},
	} {
		if field.value.Native() <= 0 {
			return fmt.Errorf("[%s] must be positive", field.name)
		}
	}
	if this.GracefulShutdownTimeout.Native() < 0 {
		return fmt.Errorf("[gracefulShutdownTimeout] must not be negative")
	}
	if this.MaxHeaderBytes == 0 || this.MaxHeaderBytes > 16<<20 {
		return fmt.Errorf("[maxHeaderBytes] must be between 1 and 16777216")
	}
	if err := this.RememberMe.Validate(); err != nil {
		return configurationFieldError(this, "rememberMe", err)
	}
	if err := validateHttpFilePath(this.AssetsDirectory, true); err != nil {
		return configurationFieldError(this, "assetsDirectory", err)
	}
	if err := this.CustomCss.Validate(); err != nil {
		return configurationFieldError(this, "customCss", err)
	}
	if err := this.CustomJs.Validate(); err != nil {
		return configurationFieldError(this, "customJs", err)
	}
	return nil
}

func (this *Http) UnmarshalYAML(node *yaml.Node) error {
	if err := this.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	if err := func(target *Http, node *yaml.Node) error {
		fields, err := effectiveHttpFields(node)
		if err != nil {
			return err
		}
		target.tlsExplicitNull = fields["tls"].Tag == "!!null"
		type raw Http
		return decodeHttpFields(node, (*raw)(target), map[string]string{
			"webUi": "!!map", "sshTunnel": "!!map", "loginFlow": "!!map",
			"enabled": "!!bool|!!str", "addresses": "!!seq/!!str", "domains": "!!seq/!!str", "tls": "!!map|!!str|!!null", "upstream": "!!map",
			"startupTimeout": "!!str", "readHeaderTimeout": "!!str", "idleTimeout": "!!str", "gracefulShutdownTimeout": "!!str", "maxHeaderBytes": "!!int",
			"rememberMe": "!!map", "assetsDirectory": "!!str", "customCss": "!!seq/!!str", "customJs": "!!seq/!!str", "customHtmlHead": "!!str", "customHtmlBody": "!!str",
		})
	}(this, node); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	if err := this.trim(false); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	return nil
}

func (this Http) MarshalYAML() (any, error) {
	type raw Http
	if this.Tls == nil && this.tlsExplicitNull {
		return marshalWithYAMLField(raw(this), "tls", nil)
	}
	return raw(this), nil
}

func (this *Http) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case Http:
		return this != nil && this.isEqualTo(&value)
	case *Http:
		if this == nil || value == nil {
			return this == value
		}
		return this.isEqualTo(value)
	default:
		return false
	}
}
func (this *Http) isEqualTo(other *Http) bool {
	return this.Enabled == other.Enabled && this.WebUi.IsEqualTo(other.WebUi) && this.SshTunnel.IsEqualTo(other.SshTunnel) && this.LoginFlow.IsEqualTo(other.LoginFlow) &&
		this.Addresses.IsEqualTo(other.Addresses) && this.Domains.IsEqualTo(other.Domains) && this.Tls.IsEqualTo(other.Tls) &&
		(this.Tls != nil || this.tlsExplicitNull == other.tlsExplicitNull) && this.Upstream.IsEqualTo(other.Upstream) &&
		this.StartupTimeout.IsEqualTo(other.StartupTimeout) && this.ReadHeaderTimeout.IsEqualTo(other.ReadHeaderTimeout) && this.IdleTimeout.IsEqualTo(other.IdleTimeout) &&
		this.GracefulShutdownTimeout.IsEqualTo(other.GracefulShutdownTimeout) && this.MaxHeaderBytes == other.MaxHeaderBytes && this.RememberMe == other.RememberMe &&
		this.AssetsDirectory == other.AssetsDirectory && slices.Equal(this.CustomCss, other.CustomCss) && slices.Equal(this.CustomJs, other.CustomJs) &&
		this.CustomHtmlHead == other.CustomHtmlHead && this.CustomHtmlBody == other.CustomHtmlBody
}

type HttpRememberMe struct {
	IdleTimeout common.Duration `yaml:"idleTimeout,omitempty"`
}

func (this *HttpRememberMe) SetDefaults() error {
	this.IdleTimeout = DefaultHttpRememberMeIdleTimeout
	return nil
}
func (this *HttpRememberMe) Trim() error { return this.Validate() }
func (this *HttpRememberMe) Validate() error {
	if this.IdleTimeout.Native() <= 0 {
		return fmt.Errorf("[idleTimeout] must be positive")
	}
	return nil
}
func (this *HttpRememberMe) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *HttpRememberMe, node *yaml.Node) error {
		type raw HttpRememberMe
		return decodeHttpFields(node, (*raw)(target), map[string]string{"idleTimeout": "!!str"})
	})
}

// HttpAssetFiles are local files appended after built-in resources. They are not
// remote URLs, HTML snippets or browser-supplied paths.
type HttpAssetFiles []string

func (this HttpAssetFiles) Validate() error {
	for index, value := range this {
		if err := validateHttpFilePath(value, false); err != nil {
			return fmt.Errorf("[%d] %w", index, err)
		}
	}
	return nil
}
func (this *HttpAssetFiles) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("asset files must be a sequence")
	}
	for _, entry := range node.Content {
		if entry.Kind == yaml.AliasNode && entry.Alias != nil {
			entry = entry.Alias
		}
		if entry.Tag != "!!str" {
			return reportYamlRelatedErrf(entry, "asset file must be a string")
		}
	}
	type raw HttpAssetFiles
	if err := node.Decode((*raw)(this)); err != nil {
		return err
	}
	return this.Validate()
}
