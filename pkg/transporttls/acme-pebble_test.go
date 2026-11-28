package transporttls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pebbleca "github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const pebbleTestProcessEnv = "BIFROEST_TEST_EMBEDDED_PEBBLE"

type pebbleTestConfig struct {
	ValidationIP string
	TLSPort      int
	Domains      []string
	Validity     uint64
	GateOrders   bool
}

type pebbleTestReady struct {
	URL, Root, Trust string
}

type pebbleTestCounts struct {
	Registrations, Finalizations, Challenges int64
}

type pebbleTestCA struct {
	t         *testing.T
	url       string
	root      *x509.Certificate
	trust     []byte
	client    *http.Client
	done      <-chan struct{}
	closeOnce sync.Once
	stop      func()
}

// Pebble has no VA shutdown API. Re-executing this test binary isolates its
// workers, without installing or starting an external CA executable.
func newPebbleTestCA(t *testing.T, address string, domains []string, validity uint64, gateOrders bool) *pebbleTestCA {
	t.Helper()
	target, err := net.ResolveTCPAddr("tcp", address)
	require.NoError(t, err)
	config, err := json.Marshal(pebbleTestConfig{
		ValidationIP: target.IP.String(), TLSPort: target.Port, Domains: domains,
		Validity: validity, GateOrders: gateOrders,
	})
	require.NoError(t, err)
	binary, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, binary, "-test.run=^TestEmbeddedACMECAProcess$", "-test.timeout=5m")
	command.Env = append(os.Environ(), pebbleTestProcessEnv+"="+string(config))
	trace := newACMETestTrace()
	command.Stderr = trace
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	input, err := command.StdinPipe()
	require.NoError(t, err)
	command.WaitDelay = 5 * time.Second
	if err := command.Start(); err != nil {
		cancel()
		_ = input.Close()
		_ = output.Close()
		require.NoError(t, err)
	}
	done, readDone := make(chan struct{}), make(chan struct{})
	var processErr error
	go func() { processErr = command.Wait(); close(done) }()
	ca := &pebbleTestCA{t: t, done: done}
	ca.stop = func() {
		defer cancel()
		_ = input.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cancel()
			<-done
			t.Error("embedded Pebble did not stop after closing its control pipe")
		}
		<-readDone
		if ca.client != nil {
			ca.client.CloseIdleConnections()
		}
		if processErr != nil {
			t.Errorf("embedded Pebble did not exit cleanly: %v", processErr)
		}
		if t.Failed() {
			t.Logf("embedded Pebble:\n%s", trace.String())
		}
	}
	t.Cleanup(ca.Close)
	type startup struct {
		ready pebbleTestReady
		err   error
	}
	started := make(chan startup, 1)
	go func() {
		defer close(readDone)
		var result startup
		result.err = json.NewDecoder(output).Decode(&result.ready)
		started <- result
		_, _ = io.Copy(trace, output)
	}()
	var ready pebbleTestReady
	select {
	case result := <-started:
		require.NoError(t, result.err, "embedded Pebble startup:\n%s", trace.String())
		ready = result.ready
	case <-done:
		t.Fatalf("embedded Pebble exited during startup: %v\n%s", processErr, trace.String())
	case <-time.After(15 * time.Second):
		t.Fatal("embedded Pebble did not report its bound listener")
	}
	ca.url, ca.trust = ready.URL, []byte(ready.Trust)
	block, _ := pem.Decode([]byte(ready.Root))
	require.NotNil(t, block)
	ca.root, err = x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.trust))
	ca.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
	}}
	return ca
}

func (this *pebbleTestCA) Close() { this.closeOnce.Do(this.stop) }

func (this *pebbleTestCA) directory() string { return this.url + wfe.DirectoryPath }

func (this *pebbleTestCA) counts() pebbleTestCounts {
	this.t.Helper()
	response, err := this.client.Get(this.url + "/fixture/counts")
	require.NoError(this.t, err)
	defer response.Body.Close()
	require.Equal(this.t, http.StatusOK, response.StatusCode)
	var result pebbleTestCounts
	require.NoError(this.t, json.NewDecoder(response.Body).Decode(&result))
	return result
}

type pebbleTestResponse struct {
	http.ResponseWriter
	status int
}

func (this *pebbleTestResponse) WriteHeader(status int) {
	this.status = status
	this.ResponseWriter.WriteHeader(status)
}

// This is only selected in the child process started by newPebbleTestCA.
func TestEmbeddedACMECAProcess(t *testing.T) {
	raw := os.Getenv(pebbleTestProcessEnv)
	if raw == "" {
		return
	}
	var config pebbleTestConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &config))
	require.NotEmpty(t, config.Domains)
	ip := net.ParseIP(config.ValidationIP)
	require.NotNil(t, ip)
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")
	t.Setenv("PEBBLE_VA_ALWAYS_VALID", "0")
	t.Setenv("PEBBLE_AUTHZREUSE", "0")
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	resolver := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		for _, question := range request.Question {
			if !slices.Contains(config.Domains, strings.TrimSuffix(strings.ToLower(question.Name), ".")) {
				response.Rcode = dns.RcodeNameError
				continue
			}
			header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET}
			if question.Qtype == dns.TypeA && ip.To4() != nil {
				response.Answer = append(response.Answer, &dns.A{Hdr: header, A: ip.To4()})
			} else if question.Qtype == dns.TypeAAAA && ip.To4() == nil {
				response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: ip})
			}
		}
		_ = w.WriteMsg(response)
	})}
	resolverDone := make(chan error, 1)
	go func() { resolverDone <- resolver.ActivateAndServe() }()
	t.Cleanup(func() {
		require.NoError(t, resolver.Shutdown())
		require.NoError(t, <-resolverDone)
	})
	logger := log.New(os.Stderr, "Pebble: ", 0)
	store := db.NewMemoryStore()
	issuer := pebbleca.New(logger, store, "", "ecdsa", 0, 1, map[string]pebbleca.Profile{
		"default": {ValidityPeriod: config.Validity},
	})
	validator := va.New(logger, 0, config.TLSPort, false, listener.Addr().String(), store)
	frontend := wfe.New(logger, store, validator, issuer, []string{"pebble.letsencrypt.org"}, false, false, 0, 0)
	handler := frontend.Handler()
	begin := make(chan struct{})
	var beginOnce sync.Once
	if !config.GateOrders {
		beginOnce.Do(func() { close(begin) })
	}
	var registrations, finalizations, challenges atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fixture/begin":
			beginOnce.Do(func() { close(begin) })
			w.WriteHeader(http.StatusOK)
			return
		case "/fixture/counts":
			_ = json.NewEncoder(w).Encode(pebbleTestCounts{registrations.Load(), finalizations.Load(), challenges.Load()})
			return
		case "/order-plz":
			select {
			case <-begin:
			case <-r.Context().Done():
				return
			}
		}
		response := &pebbleTestResponse{ResponseWriter: w, status: http.StatusOK}
		handler.ServeHTTP(response, r)
		if r.Method == http.MethodPost {
			switch {
			case r.URL.Path == "/sign-me-up" && response.status == http.StatusCreated:
				registrations.Add(1)
			case strings.HasPrefix(r.URL.Path, "/finalize-order/") && response.status == http.StatusOK:
				finalizations.Add(1)
			case strings.HasPrefix(r.URL.Path, "/chalZ/") && response.status == http.StatusOK:
				challenges.Add(1)
			}
		}
	}))
	t.Cleanup(server.Close)
	ready := pebbleTestReady{URL: server.URL,
		Root:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.GetRootCert(0).DER})),
		Trust: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
	}
	require.NoError(t, json.NewEncoder(os.Stdout).Encode(ready))
	_, err = io.Copy(io.Discard, os.Stdin)
	beginOnce.Do(func() { close(begin) })
	require.NoError(t, err)
}

func TestEmbeddedACMECAStopsWithItsOwningTest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	var ca *pebbleTestCA
	t.Run("CA lifetime", func(t *testing.T) {
		ca = newPebbleTestCA(t, listener.Addr().String(), []string{"app.example.org"}, 3600, false)
		require.Zero(t, ca.counts().Registrations)
	})
	select {
	case <-ca.done:
	default:
		t.Fatal("Pebble process survived the owning test's cleanup")
	}
	address, err := url.Parse(ca.url)
	require.NoError(t, err)
	connection, err := net.DialTimeout("tcp", address.Host, time.Second)
	if connection != nil {
		_ = connection.Close()
	}
	require.Error(t, err, "CA listener must be closed by test cleanup")
}

func TestACMEWithEmbeddedPebbleIssuesRenewsAndRestartsOffline(t *testing.T) {
	domains := []string{"first.example.org", "second.example.org"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	ca := newPebbleTestCA(t, listener.Addr().String(), domains, 15, false)
	conf := newTlsTestConfiguration(t, domains...)
	conf.Tls.Acme.DirectoryUrl = ca.directory()
	conf.Tls.Acme.Storage = filepath.Join(t.TempDir(), "acme")
	source, err := newACME(conf, ca.client, time.Now)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, source.Close()) })
	var active atomic.Pointer[TLS]
	config := &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if manager := active.Load(); manager != nil {
			return manager.configForClient(hello)
		}
		return nil, ErrNotReady
	}}
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- serveACMETestTLS(ctx, listener, config, newACMETestTrace()) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		require.NoError(t, <-served)
	})
	prepare := func(certificateSource CertificateSource) *TLS {
		t.Helper()
		manager, err := newTLS(conf, certificateSource, time.Now)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, manager.Close()) })
		active.Store(manager)
		require.NoError(t, manager.Prepare(t.Context()))
		require.True(t, manager.Ready())
		return manager
	}
	first := prepare(source)
	initialCounts := ca.counts()
	require.EqualValues(t, len(domains), initialCounts.Challenges, "every new identifier must complete TLS-ALPN-01 validation")
	account, err := source.store.read("account.pem")
	require.NoError(t, err)
	before := make(map[string]string)
	var renewAt time.Time
	for _, domain := range domains {
		selected, err := first.Config().GetConfigForClient(testClientHello(domain, "h2"))
		require.NoError(t, err)
		before[domain] = selected.Certificates[0].Leaf.SerialNumber.String()
		due := certificateRenewalAt(first.certificates[domain])
		if due.After(renewAt) {
			renewAt = due
		}
	}
	// Short-lived real certificates exercise the core's due-date calculation.
	timer := time.NewTimer(time.Until(renewAt) + 50*time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	require.NoError(t, first.RenewDue(t.Context()))
	for _, domain := range domains {
		after, err := first.Config().GetConfigForClient(testClientHello(domain, "h2"))
		require.NoError(t, err)
		require.NotEqual(t, before[domain], after.Certificates[0].Leaf.SerialNumber.String())
		roots := x509.NewCertPool()
		roots.AddCert(ca.root)
		connection, err := (&tls.Dialer{Config: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: domain,
		}}).DialContext(t.Context(), "tcp", listener.Addr().String())
		require.NoError(t, err)
		require.NoError(t, connection.Close())
	}
	stored, err := source.store.read("account.pem")
	require.NoError(t, err)
	require.Equal(t, account, stored)
	counts := ca.counts()
	require.EqualValues(t, 1, counts.Registrations)
	require.EqualValues(t, 4, counts.Finalizations)
	// Pebble's inclusive random comparison can reuse a valid authorization
	// even with PEBBLE_AUTHZREUSE=0. Renewal may legitimately need no new proof.
	require.GreaterOrEqual(t, counts.Challenges, initialCounts.Challenges)
	require.LessOrEqual(t, counts.Challenges, counts.Finalizations)
	require.NoError(t, source.Close())
	ca.Close()
	restarted, err := newACME(conf, ca.client, time.Now)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	prepare(restarted)
}
