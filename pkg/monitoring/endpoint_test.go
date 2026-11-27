package monitoring

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func endpointTestConfiguration(t *testing.T) *configuration.Monitoring {
	t.Helper()
	result := new(configuration.Monitoring)
	require.NoError(t, result.SetDefaults())
	result.Enabled = true
	result.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:0")}
	return result
}
func endpointTestRegistry() *prometheus.Registry {
	result := prometheus.NewRegistry()
	result.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{Name: "bifroest_test", Help: "Test."}))
	return result
}
func endpointRequest(endpoint *Endpoint, path, peer, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.RemoteAddr = peer
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	request.Header.Set("Forwarded", "for=127.0.0.1")
	if token != "" {
		request.Header.Set("Authorization", token)
	}
	response := httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	return response
}

func TestEndpointLifecycleAndToken(t *testing.T) {
	conf := endpointTestConfiguration(t)
	conf.BearerToken = "secret-token"
	endpoint, err := New(conf, endpointTestRegistry())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, endpointRequest(endpoint, "/status", "192.0.2.1:10", "").Code)
	require.Equal(t, http.StatusServiceUnavailable, endpointRequest(endpoint, "/ready", "192.0.2.1:10", "").Code)
	endpoint.SetReady(true)
	require.Equal(t, http.StatusOK, endpointRequest(endpoint, "/ready", "192.0.2.1:10", "").Code)
	for _, token := range []string{"", "secret-token", "Basic secret-token", "Bearer wrong", "Bearer secret-token ", "Bearer secret-token, Bearer secret-token"} {
		require.Equal(t, http.StatusUnauthorized, endpointRequest(endpoint, "/metrics", "192.0.2.1:10", token).Code)
	}
	response := endpointRequest(endpoint, "/metrics", "192.0.2.1:10", "bearer secret-token")
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), "bifroest_test 0")
	require.NotContains(t, response.Body.String(), "secret-token")
	require.Equal(t, http.StatusNotFound, endpointRequest(endpoint, "/debug/pprof/", "192.0.2.1:10", "").Code)
	request := httptest.NewRequest(http.MethodPost, "/ready", nil)
	response = httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	require.Equal(t, http.StatusMethodNotAllowed, response.Code)
	endpoint.SetReady(false)
	require.Equal(t, http.StatusServiceUnavailable, endpointRequest(endpoint, "/ready", "192.0.2.1:10", "").Code)
}

func TestEndpointPeerFilter(t *testing.T) {
	conf := endpointTestConfiguration(t)
	conf.AllowedRemoteHosts = []string{"192.0.2.42/24", "2001:db8::/32", "::1", "::ffff:198.51.100.1/120"}
	endpoint, err := New(conf, endpointTestRegistry())
	require.NoError(t, err)
	for _, peer := range []string{"192.0.2.1:123", "[2001:db8::1]:123", "[::1]:123", "[::ffff:192.0.2.1]:123", "198.51.100.1:123"} {
		require.Equal(t, http.StatusOK, endpointRequest(endpoint, "/status", peer, "").Code, peer)
	}
	for _, peer := range []string{"203.0.113.1:123", "[2001:db9::1]:123", "127.0.0.1:123", "not-an-ip:123", "192.0.2.1", ""} {
		for _, path := range []string{"/status", "/ready", "/metrics"} {
			require.Equal(t, http.StatusForbidden, endpointRequest(endpoint, path, peer, "").Code, peer)
		}
	}
}

func TestEndpointUnknownPathsHaveEmptyNotFoundResponses(t *testing.T) {
	conf := endpointTestConfiguration(t)
	conf.BearerToken = "secret-token"
	endpoint, err := New(conf, endpointTestRegistry())
	require.NoError(t, err)
	server := httptest.NewServer(endpoint)
	t.Cleanup(server.Close)
	client := server.Client()
	for _, path := range []string{"/", "/missing", "/metrics/", "/ready/", "/debug/pprof/"} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
			t.Run(method+path, func(t *testing.T) {
				request, err := http.NewRequest(method, server.URL+path, nil)
				require.NoError(t, err)
				response, err := client.Do(request)
				require.NoError(t, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, http.StatusNotFound, response.StatusCode)
				require.Empty(t, body)
				require.Empty(t, response.Header.Get("Content-Type"))
				require.Empty(t, response.Header.Get("WWW-Authenticate"))
			})
		}
	}
}

func TestEndpointTokenFilesAndDisabledMode(t *testing.T) {
	conf := endpointTestConfiguration(t)
	conf.BearerTokenFile = filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(conf.BearerTokenFile, []byte("file-secret\n"), 0600))
	endpoint, err := New(conf, endpointTestRegistry())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, endpointRequest(endpoint, "/metrics", "127.0.0.1:1", "Bearer file-secret").Code)
	for _, content := range []string{"", "\n", "bad secret", "secret\nsecond"} {
		require.NoError(t, os.WriteFile(conf.BearerTokenFile, []byte(content), 0600))
		_, err := New(conf, endpointTestRegistry())
		require.Error(t, err)
		require.NotContains(t, err.Error(), content+"second")
	}
	conf.Enabled = false
	conf.BearerTokenFile = "missing"
	conf.Tls = &configuration.Tls{}
	conf.Tls.Certificates = []configuration.TlsCertificate{{CertificateFile: "missing", PrivateKeyFile: "missing"}}
	endpoint, err = New(conf, nil)
	require.NoError(t, err)
	require.Nil(t, endpoint)
}

func TestEndpointRealListenerAndConcurrentScrapes(t *testing.T) {
	endpoint, err := New(endpointTestConfiguration(t), endpointTestRegistry())
	require.NoError(t, err)
	require.NoError(t, endpoint.Start(func(err error) { t.Errorf("unexpected listener error: %v", err) }))
	t.Cleanup(func() { require.NoError(t, endpoint.Close()) })
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + endpoint.listeners[0].Addr().String() + "/status")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.NoError(t, response.Body.Close())
	var wait sync.WaitGroup
	for index := 0; index < 3; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 20; iteration++ {
				endpoint.SetReady(iteration%2 == 0)
				response := endpointRequest(endpoint, "/metrics", "127.0.0.1:1", "")
				if response.Code != http.StatusOK {
					t.Errorf("scrape: %d", response.Code)
				}
			}
		}()
	}
	wait.Wait()
	require.NoError(t, endpoint.Close())
	require.False(t, endpoint.Ready())
}

func TestEndpointTLSWithProvidedCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	directory := t.TempDir()
	certPath := filepath.Join(directory, "cert.pem")
	keyPath := filepath.Join(directory, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, bfcrypto.WriteBootstrapFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), false))
	conf := endpointTestConfiguration(t)
	conf.Domains = configuration.ServerNames{"127.0.0.1"}
	conf.Tls = &configuration.Tls{Certificates: []configuration.TlsCertificate{{CertificateFile: certPath, PrivateKeyFile: keyPath}}}
	endpoint, err := New(conf, endpointTestRegistry())
	require.NoError(t, err)
	require.NoError(t, endpoint.Start(nil))
	t.Cleanup(func() { require.NoError(t, endpoint.Close()) })
	roots := x509.NewCertPool()
	roots.AddCert(templateCertificate(t, der))
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + endpoint.listeners[0].Addr().String() + "/status")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.NoError(t, response.Body.Close())
	conf.Tls.Certificates[0].PrivateKeyFile = "missing"
	_, err = New(conf, endpointTestRegistry())
	require.Error(t, err)
}

func templateCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

func TestEndpointInlineDummyTLSBindsOnlyConfiguredNamesAndNeverServesChallenges(t *testing.T) {
	for _, domains := range []configuration.ServerNames{{"metrics.example.org"}, {"metrics.example.org", "second.example.org"}} {
		conf := endpointTestConfiguration(t)
		conf.Domains = domains
		conf.Tls = &configuration.Tls{Dummy: true, MinVersion: "1.2"}
		endpoint, err := New(conf, endpointTestRegistry())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, endpoint.Close()) })
		for _, name := range domains {
			selected, err := endpoint.server.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{ServerName: name})
			require.NoError(t, err)
			require.Equal(t, uint16(tls.VersionTLS12), selected.MinVersion)
		}
		_, err = endpoint.server.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{})
		if len(domains) == 1 {
			require.NoError(t, err, "single-identity monitoring permits probes without SNI")
		} else {
			require.Error(t, err, "multiple identities require SNI")
		}
		for _, hello := range []*tls.ClientHelloInfo{
			{ServerName: "unconfigured.example.org"},
			{ServerName: domains[0], SupportedProtos: []string{"acme-tls/1"}},
		} {
			_, err := endpoint.server.TLSConfig.GetConfigForClient(hello)
			require.Error(t, err)
		}
	}
}

func TestEndpointPartialBindRollsBack(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()
	conf := endpointTestConfiguration(t)
	conf.Addresses = append(conf.Addresses, bnet.MustNewAddress(occupied.Addr().String()))
	endpoint, err := New(conf, endpointTestRegistry())
	require.NoError(t, err)
	require.Error(t, endpoint.Start(nil))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.listeners[0].Addr().String())
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err)
}

var _ io.Closer = (*Endpoint)(nil)

type endpointFailureCollector struct{ description *prometheus.Desc }

func (this endpointFailureCollector) Describe(ch chan<- *prometheus.Desc) { ch <- this.description }
func (this endpointFailureCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.NewInvalidMetric(this.description, fmt.Errorf("private collector data and /private/path"))
}

func TestEndpointScrapeFailureIsSanitizedAndDoesNotAffectProbes(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(endpointFailureCollector{prometheus.NewDesc("broken_test", "Test.", nil, nil)})
	endpoint, err := New(endpointTestConfiguration(t), registry)
	require.NoError(t, err)
	endpoint.SetReady(true)
	response := endpointRequest(endpoint, "/metrics", "127.0.0.1:1", "")
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.Equal(t, "metrics unavailable\n", response.Body.String())
	for _, path := range []string{"/ready", "/status"} {
		require.Equal(t, http.StatusOK, endpointRequest(endpoint, path, "127.0.0.1:1", "").Code)
	}
}

func TestEndpointOpenMetricsAndRepeatedAuthorization(t *testing.T) {
	conf := endpointTestConfiguration(t)
	conf.BearerToken = "secret"
	endpoint, err := New(conf, endpointTestRegistry())
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("Accept", "application/openmetrics-text; version=1.0.0; charset=utf-8")
	response := httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Header().Get("Content-Type"), "application/openmetrics-text")
	require.Contains(t, response.Body.String(), "# EOF\n")
	request.Header.Add("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	require.Equal(t, http.StatusUnauthorized, response.Code)
}
