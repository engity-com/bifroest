package configuration

import (
	"crypto/tls"
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
)

const DefaultHttpAcmeDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory"

// Tls is the shared server TLS definition. Consumers may also select a named
// root definition; definitions themselves cannot form reference chains.
type Tls struct {
	Reference      string `yaml:"-"`
	definition     *Tls
	implicit       bool
	MinVersion     string           `yaml:"minVersion,omitempty"`
	Dummy          bool             `yaml:"dummy,omitempty"`
	Certificates   []TlsCertificate `yaml:"certificates,omitempty"`
	Acme           *TlsAcme         `yaml:"acme"`
	ReloadInterval common.Duration  `yaml:"reloadInterval,omitempty"`
}
type HttpTls = Tls

func (this *Tls) IsEnabled() bool { return this != nil }

// ServerDefinition returns an independent effective definition, without reading
// files or changing the configured inline/reference representation.
func (this *Tls) ServerDefinition() (Tls, error) {
	if this == nil {
		return Tls{}, fmt.Errorf("TLS is not configured")
	}
	if this.Reference != "" {
		if this.definition == nil {
			return Tls{}, fmt.Errorf("unresolved TLS reference")
		}
		return this.definition.ServerDefinition()
	}
	result := cloneConfigurationValue(*this)
	result.Certificates = this.FileCertificates()
	return result, nil
}

func (this Tls) MinimumVersion() uint16 {
	if this.MinVersion == "1.2" {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

func (this Tls) ReloadEvery() time.Duration {
	if this.ReloadInterval.Native() == 0 {
		return 5 * time.Second
	}
	return this.ReloadInterval.Native()
}

// FileCertificates selects defaults lazily, without changing ACME/dummy source
// selection or making a disabled listener touch the filesystem.
func (this *Tls) FileCertificates() []TlsCertificate {
	if this == nil {
		return nil
	}
	if this.Reference != "" {
		if this.definition == nil {
			return nil
		}
		return this.definition.FileCertificates()
	}
	if this.Dummy {
		return nil
	}
	if len(this.Certificates) != 0 {
		return slices.Clone(this.Certificates)
	}
	if this.Acme.IsEnabled() {
		return nil
	}
	return []TlsCertificate{{CertificateFile: DefaultHttpCertificateFile, PrivateKeyFile: DefaultHttpPrivateKeyFile}}
}

func (this *Tls) SetDefaults() error {
	*this = Tls{}
	return nil
}
func (this *Tls) Trim() error {
	if this == nil {
		return nil
	}
	for index := range this.Certificates {
		if err := this.Certificates[index].Trim(); err != nil {
			return fmt.Errorf("[certificates][%d] %w", index, err)
		}
	}
	if err := this.Acme.Trim(); err != nil {
		return configurationFieldError(this, "acme", err)
	}
	return this.Validate()
}
func (this *Tls) Validate() error {
	if this == nil {
		return nil
	}
	if this.Reference != "" {
		if this.MinVersion != "" || this.Dummy || len(this.Certificates) != 0 || this.Acme.IsEnabled() || this.ReloadInterval.Native() != 0 {
			return fmt.Errorf("TLS reference cannot be combined with inline settings")
		}
		return validateDefinitionName(this.Reference)
	}
	if this.MinVersion != "" && this.MinVersion != "1.2" && this.MinVersion != "1.3" {
		return fmt.Errorf("[minVersion] must be 1.2 or 1.3")
	}
	if this.ReloadInterval.Native() < 0 {
		return fmt.Errorf("[reloadInterval] must be positive")
	}
	if this.Dummy && (len(this.Certificates) > 0 || this.Acme.IsEnabled()) {
		return fmt.Errorf("[dummy] cannot be combined with certificates or ACME")
	}
	for index := range this.Certificates {
		if err := this.Certificates[index].Validate(); err != nil {
			return fmt.Errorf("[certificates][%d] %w", index, err)
		}
	}
	// Runtime TLS validation stays confined to the concrete TLS settings.
	if err := this.Acme.Validate(); err != nil {
		return configurationFieldError(this, "acme", err)
	}
	return nil
}
func (this *Tls) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		if node.Value == "" {
			*this = Tls{Reference: "default", implicit: true}
			return nil
		}
		if err := validateDefinitionName(node.Value); err != nil {
			return err
		}
		*this = Tls{Reference: node.Value}
		return nil
	}
	return unmarshalYAML(this, node, func(target *Tls, node *yaml.Node) error {
		type raw Tls
		return decodeHttpFields(node, (*raw)(target), map[string]string{"dummy": "!!bool", "minVersion": "!!str", "certificates": "!!seq/!!map", "acme": "!!map|!!null", "reloadInterval": "!!str"})
	})
}
func (this Tls) MarshalYAML() (any, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	if this.Reference != "" {
		if this.implicit {
			return "", nil
		}
		return this.Reference, nil
	}
	type raw Tls
	return raw(this), nil
}
func (this *Tls) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case Tls:
		return this.IsEqualTo(&value)
	case *Tls:
		return this.isEqualTo(value)
	default:
		return false
	}
}

func (this *Tls) isEqualTo(value *Tls) bool {
	if this == nil || value == nil {
		return this == value
	}
	if this.Reference != "" || value.Reference != "" {
		return this.Reference == value.Reference && this.implicit == value.implicit && this.Validate() == nil && value.Validate() == nil
	}
	return this.MinimumVersion() == value.MinimumVersion() &&
		this.ReloadEvery() == value.ReloadEvery() &&
		this.Dummy == value.Dummy && slices.Equal(this.Certificates, value.Certificates) && this.Acme.isEqualTo(value.Acme)
}

type TlsCertificate struct {
	CertificateFile string `yaml:"certificateFile"`
	PrivateKeyFile  string `yaml:"privateKeyFile" sensitive:"true"`
}
type HttpCertificate = TlsCertificate

func (this *TlsCertificate) SetDefaults() error {
	*this = TlsCertificate{}
	return nil
}
func (this *TlsCertificate) Trim() error {
	this.CertificateFile = strings.TrimSpace(this.CertificateFile)
	this.PrivateKeyFile = strings.TrimSpace(this.PrivateKeyFile)
	return this.Validate()
}
func (this *TlsCertificate) Validate() error {
	if err := validateHttpFilePath(this.CertificateFile, false); err != nil {
		return configurationFieldError(this, "certificateFile", err)
	}
	if err := validateHttpFilePath(this.PrivateKeyFile, false); err != nil {
		return configurationFieldError(this, "privateKeyFile", err)
	}
	return nil
}
func (this *TlsCertificate) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *TlsCertificate, node *yaml.Node) error {
		type raw TlsCertificate
		return decodeHttpFields(node, (*raw)(target), map[string]string{"certificateFile": "!!str", "privateKeyFile": "!!str"})
	})
}

type TlsAcme struct {
	AcceptTerms  bool   `yaml:"acceptTerms,omitempty"`
	Email        string `yaml:"email,omitempty"`
	DirectoryUrl string `yaml:"directoryUrl"`
	Storage      string `yaml:"storage"`
}
type HttpAcme = TlsAcme

func (this *TlsAcme) IsEnabled() bool { return this != nil }

func (this *TlsAcme) isEqualTo(other *TlsAcme) bool {
	if this == nil || other == nil {
		return this == other
	}
	return *this == *other
}

func (this *TlsAcme) SetDefaults() error {
	*this = TlsAcme{DirectoryUrl: DefaultHttpAcmeDirectoryUrl, Storage: DefaultHttpAcmeStorage}
	return nil
}
func (this *TlsAcme) Trim() error {
	if this == nil {
		return nil
	}
	this.Email = strings.TrimSpace(this.Email)
	this.DirectoryUrl = strings.TrimSpace(this.DirectoryUrl)
	this.Storage = strings.TrimSpace(this.Storage)
	return this.Validate()
}
func (this *TlsAcme) Validate() error {
	if this == nil {
		return nil
	}
	if !this.AcceptTerms {
		return fmt.Errorf("[acceptTerms] must be true")
	}
	if this.Email != "" {
		address, err := mail.ParseAddress(this.Email)
		if err != nil || address.Address != this.Email {
			return fmt.Errorf("[email] must be a plain email address")
		}
	}
	parsed, err := url.Parse(this.DirectoryUrl)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Opaque != "" {
		return fmt.Errorf("[directoryUrl] must be an absolute HTTPS URL without credentials, query or fragment")
	}
	if _, err := net.CanonicalHttpHost(parsed.Host); err != nil {
		return fmt.Errorf("[directoryUrl] invalid HTTPS authority")
	}
	if err := validateHttpFilePath(this.Storage, false); err != nil {
		return configurationFieldError(this, "storage", err)
	}
	return nil
}
func (this *TlsAcme) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *TlsAcme, node *yaml.Node) error {
		type raw TlsAcme
		return decodeHttpFields(node, (*raw)(target), map[string]string{"acceptTerms": "!!bool", "email": "!!str", "directoryUrl": "!!str", "storage": "!!str"})
	})
}

func validateHttpFilePath(value string, optional bool) error {
	if strings.TrimSpace(value) == "" && !optional {
		return fmt.Errorf("required but absent")
	}
	if strings.ContainsAny(value, "\x00\r\n") || strings.Contains(value, "://") {
		return fmt.Errorf("must be a local filesystem path")
	}
	return nil
}
