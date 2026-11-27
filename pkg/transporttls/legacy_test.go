package transporttls

import (
	"fmt"
	"net/http"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// Run the original HTTP certificate regression suite against the extracted core.
// Only this test adapter knows HTTP; production constructors take neutral Config.
func legacyConfig(conf *configuration.Http) (Config, error) {
	if !conf.IsEnabled() {
		return Config{}, fmt.Errorf("HTTP is disabled")
	}
	if err := conf.Validate(); err != nil {
		return Config{}, err
	}
	profile, err := conf.Tls.ServerDefinition()
	return Config{Profile: profile, Names: conf.Domains,
		StartupTimeout: conf.StartupTimeout.Native(), NextProtos: []string{"h2", "http/1.1"}}, err
}
func NewTLS(conf *configuration.Http, source CertificateSource) (*TLS, error) {
	return newTLS(conf, source, time.Now)
}
func newTLS(conf *configuration.Http, source CertificateSource, now func() time.Time) (*TLS, error) {
	adapted, err := legacyConfig(conf)
	if err != nil {
		return nil, err
	}
	return newTLSConfig(adapted, source, now)
}
func NewACME(conf *configuration.Http) (*ACME, error) {
	return newACME(conf, &http.Client{}, time.Now)
}
func newACME(conf *configuration.Http, client *http.Client, now func() time.Time) (*ACME, error) {
	adapted, err := legacyConfig(conf)
	if err != nil {
		return nil, err
	}
	return newACMEConfig(adapted, client, now)
}
