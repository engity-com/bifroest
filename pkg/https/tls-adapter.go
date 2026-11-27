package https

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

// HTTP adapters use the shared transport TLS types.
type TLS = transporttls.TLS
type ACME = transporttls.ACME
type Challenge = transporttls.Challenge
type CertificateSource = transporttls.CertificateSource
type RenewableCertificateSource = transporttls.RenewableCertificateSource
type KeyValidator = transporttls.KeyValidator

var (
	ErrNotReady = transporttls.ErrNotReady
	ErrClosed   = transporttls.ErrClosed
)

func LoadCertificate(configured configuration.HttpCertificate, now time.Time) (*tls.Certificate, error) {
	return transporttls.LoadCertificate(configured, now)
}

func tlsConfiguration(conf *configuration.Http) (transporttls.Config, error) {
	if !conf.IsEnabled() {
		return transporttls.Config{}, fmt.Errorf("HTTP is disabled")
	}
	if err := conf.Validate(); err != nil {
		return transporttls.Config{}, err
	}
	profile, err := conf.Tls.ServerDefinition()
	if err != nil {
		return transporttls.Config{}, err
	}
	return transporttls.Config{Profile: profile, Names: conf.Domains,
		StartupTimeout: conf.StartupTimeout.Native(), NextProtos: []string{"h2", "http/1.1"}}, nil
}
func NewTLS(conf *configuration.Http, source CertificateSource) (*TLS, error) {
	adapted, err := tlsConfiguration(conf)
	if err != nil {
		return nil, err
	}
	return transporttls.New(adapted, source)
}
func NewACME(conf *configuration.Http) (*ACME, error) {
	adapted, err := tlsConfiguration(conf)
	if err != nil {
		return nil, err
	}
	return transporttls.NewACMESource(adapted)
}
