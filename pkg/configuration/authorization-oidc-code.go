package configuration

import (
	"fmt"
	stdnet "net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
)

const OidcCallbackPath = "/login/callback"

var _ = RegisterAuthorizationV(func() AuthorizationV { return &AuthorizationOidcAuthorizationCode{} })

// AuthorizationOidcAuthorizationCode shares token/session policy with Device
// Authorization, but explicitly selects a different primary grant.
type AuthorizationOidcAuthorizationCode struct {
	AuthorizationOidcDeviceAuth `yaml:",inline"`
	Domain                      string          `yaml:"domain,omitempty"`
	PathPrefix                  *string         `yaml:"pathPrefix,omitempty"`
	LoginTimeout                common.Duration `yaml:"loginTimeout,omitempty"`
	origin                      string
	pathPrefix                  string
	reverseProxy                bool
}

func (this *AuthorizationOidcAuthorizationCode) SetDefaults() error {
	*this = AuthorizationOidcAuthorizationCode{LoginTimeout: common.DurationOf(2 * time.Minute)}
	return this.AuthorizationOidcDeviceAuth.SetDefaults()
}

func (this *AuthorizationOidcAuthorizationCode) Trim() error {
	this.Domain = strings.TrimSpace(this.Domain)
	if err := this.AuthorizationOidcDeviceAuth.Trim(); err != nil {
		return err
	}
	return this.Validate()
}

func (this *AuthorizationOidcAuthorizationCode) Validate() error {
	if err := this.AuthorizationOidcDeviceAuth.Validate(); err != nil {
		return err
	}
	if this.Domain != "" {
		if _, err := (HttpDomains{this.Domain}).Canonical(); err != nil {
			return fmt.Errorf("[domain] must be a configured HTTP domain without scheme, port or path")
		}
	}
	if this.PathPrefix != nil && *this.PathPrefix != "<default>" {
		if err := ValidateHttpPathPrefix(*this.PathPrefix); err != nil {
			return fmt.Errorf("[pathPrefix] %w", err)
		}
	}
	if this.LoginTimeout.Native() <= 0 || this.LoginTimeout.Native() > 10*time.Minute {
		return fmt.Errorf("[loginTimeout] must be positive and at most 10m")
	}
	return nil
}

func (this *AuthorizationOidcAuthorizationCode) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationOidcAuthorizationCode, node *yaml.Node) error {
		// Decode common sensitive fields through their original redacting
		// decoder, without invoking the embedded custom unmarshaler.
		type fields AuthorizationOidcDeviceAuth
		if err := decodeConfigurationFields(node, (*fields)(&target.AuthorizationOidcDeviceAuth)); err != nil {
			return err
		}
		raw := struct {
			Domain       string          `yaml:"domain,omitempty"`
			PathPrefix   *string         `yaml:"pathPrefix,omitempty"`
			LoginTimeout common.Duration `yaml:"loginTimeout,omitempty"`
		}{target.Domain, target.PathPrefix, target.LoginTimeout}
		if err := node.Decode(&raw); err != nil {
			return err
		}
		target.Domain, target.PathPrefix, target.LoginTimeout = raw.Domain, raw.PathPrefix, raw.LoginTimeout
		return nil
	})
}

func (this AuthorizationOidcAuthorizationCode) MarshalYAML() (any, error) {
	// yaml.v3 omits inline fields whose type implements UnmarshalYAML.
	// Remove that method set for encoding the common policy fields.
	type Common AuthorizationOidcDeviceAuth
	return struct {
		Common       `yaml:",inline"`
		Domain       string          `yaml:"domain,omitempty"`
		PathPrefix   *string         `yaml:"pathPrefix,omitempty"`
		LoginTimeout common.Duration `yaml:"loginTimeout,omitempty"`
	}{Common(this.AuthorizationOidcDeviceAuth), this.Domain, this.PathPrefix, this.LoginTimeout}, nil
}

func (this *AuthorizationOidcAuthorizationCode) Origin() string {
	return this.origin
}

// MatchesHttpOrigin retains the configured domain. Only explicit proxy mode
// may obtain the public browser port from the validated request authority.
func (this *AuthorizationOidcAuthorizationCode) MatchesHttpOrigin(origin string) bool {
	if this.origin == "" || origin == "" {
		return false
	}
	if !this.reverseProxy {
		return origin == this.origin
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	canonical, err := net.CanonicalHttpsOrigin(parsed.Host)
	if err != nil || canonical != origin {
		return false
	}
	configured, _ := url.Parse(this.origin)
	host, _ := net.CanonicalHttpHost(configured.Host)
	requested, _ := net.CanonicalHttpHost(parsed.Host)
	return host == requested
}

func (this *AuthorizationOidcAuthorizationCode) RedirectURL() string {
	if this.origin == "" {
		return ""
	}
	return this.origin + this.pathPrefix + OidcCallbackPath
}

func (this *AuthorizationOidcAuthorizationCode) EffectivePathPrefix() string { return this.pathPrefix }
func (this *AuthorizationOidcAuthorizationCode) HasExplicitPathPrefix() bool {
	return this.PathPrefix != nil && *this.PathPrefix != "<default>"
}

func (this AuthorizationOidcAuthorizationCode) IsEqualTo(other any) bool {
	var value *AuthorizationOidcAuthorizationCode
	switch v := other.(type) {
	case *AuthorizationOidcAuthorizationCode:
		value = v
	case AuthorizationOidcAuthorizationCode:
		value = &v
	}
	prefixEqual := value != nil && (this.PathPrefix == nil && value.PathPrefix == nil || this.PathPrefix != nil && value.PathPrefix != nil && *this.PathPrefix == *value.PathPrefix)
	return value != nil && prefixEqual && this.AuthorizationOidcDeviceAuth.IsEqualTo(value.AuthorizationOidcDeviceAuth) && this.Domain == value.Domain && this.LoginTimeout == value.LoginTimeout
}
func (AuthorizationOidcAuthorizationCode) Types() []string {
	return []string{"oidcAuthorizationCode", "oidc-authorization-code", "oidc_authorization_code"}
}
func (AuthorizationOidcAuthorizationCode) FeatureFlags() []string {
	return []string{"oidcAuthorizationCode"}
}

// OidcSettings identifies the shared grant/session policy without conflating
// the primary login methods or changing the legacy configuration's meaning.
func OidcSettings(value AuthorizationV) *AuthorizationOidcDeviceAuth {
	switch conf := value.(type) {
	case *AuthorizationOidcDeviceAuth:
		return conf
	case *AuthorizationOidcAuthorizationCode:
		return &conf.AuthorizationOidcDeviceAuth
	default:
		return nil
	}
}

func (this *Configuration) validateOidcDomains() error {
	for _, flow := range this.Flows {
		conf, ok := flow.Authorization.V.(*AuthorizationOidcAuthorizationCode)
		if !ok {
			continue
		}
		conf.origin = ""
		if !this.Http.IsEnabled() {
			return fmt.Errorf("[flows][%s] OIDC Authorization Code requires enabled HTTPS", flow.Name)
		}
		conf.pathPrefix = this.Http.Upstream.DefaultPrefix
		conf.reverseProxy = this.Http.Upstream.IsReverseProxy()
		if conf.HasExplicitPathPrefix() {
			conf.pathPrefix = *conf.PathPrefix
		}
		if conf.pathPrefix != "" && !this.Http.Upstream.IsReverseProxy() {
			return fmt.Errorf("OIDC pathPrefix requires HTTP upstream.mode reverseProxy")
		}
		if !this.Http.LoginFlow.IsEnabled() {
			return fmt.Errorf("[flows][%s] OIDC Authorization Code requires http.loginFlow.enabled", flow.Name)
		}
		domains, err := this.Http.Domains.Canonical()
		if err != nil || len(domains) == 0 {
			return fmt.Errorf("[flows][%s] OIDC Authorization Code requires configured HTTP domains", flow.Name)
		}
		host := domains[0]
		if conf.Domain != "" {
			host, err = net.CanonicalHttpHost(conf.Domain)
			if err != nil || !slices.Contains(domains, host) {
				return fmt.Errorf("[flows][%s][authorization][domain] is not a configured HTTP domain", flow.Name)
			}
		}
		if len(this.Http.Addresses) == 0 {
			return fmt.Errorf("OIDC Authorization Code requires an HTTP listener")
		}
		port := int(this.Http.Upstream.DefaultPort)
		if port == 0 && this.Http.Upstream.IsReverseProxy() {
			port = 443
		}
		if port == 0 {
			address, ok := this.Http.Addresses[0].Get().(*stdnet.TCPAddr)
			if !ok || address.Port <= 0 {
				return fmt.Errorf("OIDC Authorization Code requires a fixed HTTPS listener port")
			}
			port = address.Port
		}
		if port != 443 {
			host += ":" + strconv.Itoa(port)
		}
		conf.origin = "https://" + host
	}
	return nil
}
