package authorization

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
)

// DiscoveryInput describes the planned adapter input, never an actual identity
// or credential. RequestingName means that the adapter can supply a remote name.
type DiscoveryInput struct {
	Transport      connection.Transport
	RequestingName bool
}

// AuthenticationCapabilities describes configuration-level possibilities, not
// authorization or the existence of any account, credential or remembered session.
// PublicKey is a primary credential path; SessionPublicKey must never enable a
// primary key option on its own. Secretless avoids unnecessary credential prompts.
type AuthenticationCapabilities struct {
	Password                     bool
	KeyboardInteractive          bool
	PublicKey                    bool
	Secretless                   bool
	SessionPublicKey             bool
	PublicKeyCertificateRequired bool
}

// AuthenticationCapabilityProvider must be pure: no I/O, validation, template
// execution, account/session lookup or authentication-provider interaction.
// Dynamic rules remain possible until authoritative authentication evaluates them.
type AuthenticationCapabilityProvider interface {
	AuthenticationCapabilities(DiscoveryInput) AuthenticationCapabilities
}

// DiscoveryAuthorizer is mandatory for registered factories without extending
// Authorizer itself or imposing discovery on unrelated transport/test adapters.
type DiscoveryAuthorizer interface {
	CloseableAuthorizer
	AuthenticationCapabilityProvider
}

func (this DiscoveryInput) supported() bool {
	return this.Transport == connection.TransportSsh || this.Transport == connection.TransportHttp
}

func hasConfiguredUserCA(conf *configuration.UserCertificateAuthorityProperties) bool {
	return !conf.TrustedUserCAs.IsZero() || !conf.TrustedUserCAsFile.IsZero()
}

func (this *SimpleAuthorizer) AuthenticationCapabilities(input DiscoveryInput) AuthenticationCapabilities {
	if !input.supported() || !input.RequestingName || this == nil || this.conf == nil || len(this.conf.Entries) == 0 {
		return AuthenticationCapabilities{}
	}
	result := AuthenticationCapabilities{SessionPublicKey: true}
	keySource := false
	for _, entry := range this.conf.Entries {
		result.Password = result.Password || !entry.Password.IsZero() || !entry.PasswordFile.IsZero()
		keySource = keySource || !entry.AuthorizedKeys.IsZero() || !entry.AuthorizedKeysFile.IsZero()
	}
	result.KeyboardInteractive = result.Password
	ca := hasConfiguredUserCA(&this.conf.UserCertificateAuthorityProperties)
	result.PublicKey = keySource || ca
	// A configured key source may contain raw keys or CA entries. Do not inspect
	// credentials or files to refine the hint; only CA-only configuration is certain.
	result.PublicKeyCertificateRequired = ca && !keySource
	return result
}

func (this *HtpasswdAuthorizer) AuthenticationCapabilities(input DiscoveryInput) AuthenticationCapabilities {
	if !input.supported() || !input.RequestingName || this == nil || this.conf == nil {
		return AuthenticationCapabilities{}
	}
	password := !this.conf.File.IsZero() || !this.conf.Entries.IsZero()
	return AuthenticationCapabilities{Password: password, KeyboardInteractive: password, SessionPublicKey: true}
}

func (this *OidcDeviceAuthAuthorizer) AuthenticationCapabilities(input DiscoveryInput) AuthenticationCapabilities {
	if !input.supported() || this == nil || this.conf == nil {
		return AuthenticationCapabilities{}
	}
	return AuthenticationCapabilities{KeyboardInteractive: true, SessionPublicKey: true}
}

func (this *BifroestAuthorizer) AuthenticationCapabilities(input DiscoveryInput) AuthenticationCapabilities {
	if !input.supported() || !input.RequestingName || this == nil || this.conf == nil || !hasConfiguredUserCA(&this.conf.UserCertificateAuthorityProperties) {
		return AuthenticationCapabilities{}
	}
	return AuthenticationCapabilities{PublicKey: true, PublicKeyCertificateRequired: true}
}

func (this *NoneAuthorizer) AuthenticationCapabilities(input DiscoveryInput) AuthenticationCapabilities {
	if !input.supported() || this == nil || this.conf == nil {
		return AuthenticationCapabilities{}
	}
	// Existing credential adapters remain unchanged. Discovery presents the
	// secretless action rather than asking for an unused password or private key.
	return AuthenticationCapabilities{Secretless: true, SessionPublicKey: true}
}
