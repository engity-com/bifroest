package crypto

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"net/http"
	"os"
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
		if !result.AppendCertsFromPEM(raw) {
			panic("cannot parse embedded CA certificates")
		}
		if customFile := os.Getenv("SSL_CERT_FILE"); customFile != "" {
			custom, err := os.ReadFile(customFile)
			if err != nil {
				panic(err)
			}
			if !result.AppendCertsFromPEM(custom) {
				panic("cannot parse CA certificates from SSL_CERT_FILE")
			}
		}
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
