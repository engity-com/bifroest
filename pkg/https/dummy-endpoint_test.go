package https

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDummyEndpointStillValidatesKeysAndServesRealHttp2(t *testing.T) {
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Acme, conf.Tls.Dummy = nil, true
	sentinel := errors.New("key role rejected")
	_, err := NewEndpoint(conf, EndpointOptions{ValidateKey: func(crypto.PublicKey) error { return sentinel }})
	require.ErrorIs(t, err, sentinel)
	endpoint, err := NewEndpoint(conf, EndpointOptions{})
	require.NoError(t, err)
	require.NoError(t, endpoint.Prepare(t.Context()))
	selected, err := endpoint.server.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "app.example.org"})
	require.NoError(t, err)
	root := selected.Certificates[0].Leaf
	listener, _ := startEndpointTestListener(t, endpoint)
	client := endpointTestClient(t, listener, root)
	response, err := client.Get("https://app.example.org/work")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, 2, response.ProtoMajor)
	require.Equal(t, http.StatusNotImplemented, response.StatusCode)
	_, err = root.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: "app.example.org"})
	require.Error(t, err, "dummy must not invent browser/public trust")
}
