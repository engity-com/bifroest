package crypto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"net/http"
)

var (
	//go:embed ca-certs.crt
	caCertsRaw []byte

	caCerts = func(raw []byte) *x509.CertPool {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			result, err := x509.SystemCertPool()
			if err != nil {
				panic(err)
			}
			return result
		}
		result := x509.NewCertPool()
		result.AppendCertsFromPEM(raw)
		return result
	}(caCertsRaw)
)

func CaCerts() *x509.CertPool {
	return caCerts.Clone()
}

func AdjustTlsConfigWithCaCerts(tlsConfig *tls.Config) {
	tlsConfig.RootCAs = CaCerts()
}

func AdjustHttpTransportWithCaCerts(transport *http.Transport) {
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = new(tls.Config)
	}
	AdjustTlsConfigWithCaCerts(transport.TLSClientConfig)
}

func init() {
	AdjustHttpTransportWithCaCerts(http.DefaultTransport.(*http.Transport))
}
