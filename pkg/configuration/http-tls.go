package configuration

import (
	"fmt"
	"net/mail"
	"net/url"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/net"
)

const DefaultHttpAcmeDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory"

// HttpTls permits explicit certificates and optional ACME for remaining domains,
// or an explicitly selected ephemeral dummy certificate for testing only.
// File content, domain coverage and certificate validity are runtime checks.
type HttpTls struct {
	Dummy        bool              `yaml:"dummy,omitempty"`
	Certificates []HttpCertificate `yaml:"certificates,omitempty"`
	Acme         HttpAcme          `yaml:"acme"`
}

func (this *HttpTls) SetDefaults() error {
	*this = HttpTls{}
	return this.Acme.SetDefaults()
}
func (this *HttpTls) Trim() error {
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
func (this *HttpTls) Validate() error {
	if this.Dummy && (len(this.Certificates) > 0 || this.Acme.Enabled) {
		return fmt.Errorf("[dummy] cannot be combined with certificates or enabled ACME")
	}
	for index := range this.Certificates {
		if err := this.Certificates[index].Validate(); err != nil {
			return fmt.Errorf("[certificates][%d] %w", index, err)
		}
	}
	return validate(this, func(v *HttpTls) (string, validator) { return "acme", &v.Acme })
}
func (this *HttpTls) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *HttpTls, node *yaml.Node) error {
		type raw HttpTls
		return decodeHttpFields(node, (*raw)(target), map[string]string{"dummy": "!!bool", "certificates": "!!seq/!!map", "acme": "!!map"})
	})
}
func (this HttpTls) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case HttpTls:
		return this.Dummy == value.Dummy && slices.Equal(this.Certificates, value.Certificates) && this.Acme == value.Acme
	case *HttpTls:
		return value != nil && this.IsEqualTo(*value)
	default:
		return false
	}
}

type HttpCertificate struct {
	CertificateFile string `yaml:"certificateFile"`
	PrivateKeyFile  string `yaml:"privateKeyFile" sensitive:"true"`
}

func (this *HttpCertificate) SetDefaults() error {
	*this = HttpCertificate{}
	return nil
}
func (this *HttpCertificate) Trim() error {
	this.CertificateFile = strings.TrimSpace(this.CertificateFile)
	this.PrivateKeyFile = strings.TrimSpace(this.PrivateKeyFile)
	return this.Validate()
}
func (this *HttpCertificate) Validate() error {
	return validate(this,
		func(v *HttpCertificate) (string, validator) {
			return "certificateFile", validatorFunc(func() error { return validateHttpFilePath(v.CertificateFile, false) })
		},
		func(v *HttpCertificate) (string, validator) {
			return "privateKeyFile", validatorFunc(func() error { return validateHttpFilePath(v.PrivateKeyFile, false) })
		},
	)
}
func (this *HttpCertificate) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *HttpCertificate, node *yaml.Node) error {
		type raw HttpCertificate
		return decodeHttpFields(node, (*raw)(target), map[string]string{"certificateFile": "!!str", "privateKeyFile": "!!str"})
	})
}

type HttpAcme struct {
	Enabled      bool   `yaml:"enabled,omitempty"`
	AcceptTerms  bool   `yaml:"acceptTerms,omitempty"`
	Email        string `yaml:"email,omitempty"`
	DirectoryUrl string `yaml:"directoryUrl"`
	Storage      string `yaml:"storage"`
}

func (this *HttpAcme) SetDefaults() error {
	*this = HttpAcme{DirectoryUrl: DefaultHttpAcmeDirectoryUrl, Storage: DefaultHttpAcmeStorage}
	return nil
}
func (this *HttpAcme) Trim() error {
	this.Email = strings.TrimSpace(this.Email)
	this.DirectoryUrl = strings.TrimSpace(this.DirectoryUrl)
	this.Storage = strings.TrimSpace(this.Storage)
	return this.Validate()
}
func (this *HttpAcme) Validate() error {
	if this.Enabled && !this.AcceptTerms {
		return fmt.Errorf("[acceptTerms] must be true when ACME is enabled")
	}
	if this.Email != "" {
		address, err := mail.ParseAddress(this.Email)
		if err != nil || address.Address != this.Email {
			return fmt.Errorf("[email] must be a plain email address")
		}
	}
	if this.DirectoryUrl != "" || this.Enabled {
		parsed, err := url.Parse(this.DirectoryUrl)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Opaque != "" {
			return fmt.Errorf("[directoryUrl] must be an absolute HTTPS URL without credentials, query or fragment")
		}
		if _, err := net.CanonicalHttpHost(parsed.Host); err != nil {
			return fmt.Errorf("[directoryUrl] invalid HTTPS authority")
		}
	}
	if err := validateHttpFilePath(this.Storage, !this.Enabled); err != nil {
		return configurationFieldError(this, "storage", err)
	}
	return nil
}
func (this *HttpAcme) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *HttpAcme, node *yaml.Node) error {
		type raw HttpAcme
		return decodeHttpFields(node, (*raw)(target), map[string]string{"enabled": "!!bool", "acceptTerms": "!!bool", "email": "!!str", "directoryUrl": "!!str", "storage": "!!str"})
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
