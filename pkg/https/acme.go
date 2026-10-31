package https

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// ACME is a persistent, context-bound DNS/TLS-ALPN-01 certificate source. It
// starts no goroutines or timers; Close cancels and drains active operations.
type ACME struct {
	domains       configuration.HttpDomains
	configuration configuration.HttpAcme
	store         *acmeStore
	httpClient    *http.Client
	client        *acme.Client
	validateKey   KeyValidator
	timeout       time.Duration
	now           func() time.Time
	lifetime      context.Context
	cancel        context.CancelFunc
	operation     chan struct{}
	closeOnce     sync.Once
	closeErr      error
}

func NewACME(conf *configuration.Http) (*ACME, error) {
	return newACME(conf, &http.Client{}, time.Now)
}

func newACME(conf *configuration.Http, client *http.Client, now func() time.Time) (*ACME, error) {
	if !conf.IsEnabled() || !conf.Tls.Acme.Enabled {
		return nil, fmt.Errorf("HTTP ACME is disabled")
	}
	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid HTTP ACME configuration: %w", err)
	}
	domains, err := conf.Domains.Canonical()
	if err != nil {
		return nil, err
	}
	store, err := openACMEStore(conf.Tls.Acme.Storage, conf.Tls.Acme.DirectoryUrl)
	if err != nil {
		return nil, err
	}
	copyOfClient := *client
	transport := copyOfClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if standard, ok := transport.(*http.Transport); ok {
		transport = standard.Clone()
	}
	copyOfClient.Transport = httpsOnlyTransport{transport}
	lifetime, cancel := context.WithCancel(context.Background())
	return &ACME{
		domains: configuration.HttpDomains(domains), configuration: conf.Tls.Acme, store: store, httpClient: &copyOfClient,
		timeout: conf.StartupTimeout.Native(), now: now, lifetime: lifetime, cancel: cancel, operation: make(chan struct{}, 1),
	}, nil
}

func (this *ACME) Certificate(ctx context.Context, domain string, challenge Challenge) (*tls.Certificate, error) {
	return this.obtain(ctx, domain, challenge, false)
}

// Renew obtains a fresh certificate when renewal is due, persisting it before
// replacing a live one. Issuance/validation failures do not replace cached state.
func (this *ACME) Renew(ctx context.Context, domain string, challenge Challenge) (*tls.Certificate, error) {
	return this.obtain(ctx, domain, challenge, true)
}

func (this *ACME) obtain(ctx context.Context, domain string, challenge Challenge, renew bool) (*tls.Certificate, error) {
	canonical, err := (configuration.HttpDomains{domain}).Canonical()
	if err != nil {
		return nil, fmt.Errorf("invalid requested ACME domain")
	}
	domain = canonical[0]
	allowed, err := this.domains.AllowsHost(domain)
	if err != nil || !allowed {
		return nil, fmt.Errorf("ACME domain is not configured")
	}
	if _, err := netip.ParseAddr(strings.Trim(domain, "[]")); err == nil {
		return nil, fmt.Errorf("ACME DNS/TLS-ALPN-01 does not support configured IP literals; use an explicit certificate")
	}
	ctx, cancel := context.WithTimeout(ctx, this.timeout)
	stopClose := context.AfterFunc(this.lifetime, cancel)
	defer stopClose()
	defer cancel()
	select {
	case <-this.lifetime.Done():
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	case this.operation <- struct{}{}:
		defer func() { <-this.operation }()
	}
	if this.lifetime.Err() != nil {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if this.validateKey != nil {
		raw, err := this.store.read("account.pem")
		if err == nil {
			key, err := parseACMEAccountKey(raw)
			if err != nil {
				return nil, err
			}
			if err := this.validateKey(key.Public()); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	cached, err := this.store.certificate(domain)
	if this.lifetime.Err() != nil {
		return nil, ErrClosed
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if cached != nil {
		if this.validateKey != nil {
			if err := this.validateKey(cached.value.Leaf.PublicKey); err != nil {
				return nil, err
			}
		}
		if this.now().Before(cached.notBefore) {
			return nil, fmt.Errorf("stored ACME certificate is not valid yet")
		}
		if cached.validAt(this.now()) && (!renew || certificateRenewalAt(cached).After(this.now())) {
			return cached.value, nil
		}
	}
	if challenge == nil {
		return nil, fmt.Errorf("ACME issuance needs a TLS-ALPN-01 challenge publisher")
	}
	client, err := this.acmeClient(ctx)
	if err != nil {
		return nil, err
	}
	certificate, err := this.issue(ctx, client, domain, challenge)
	if err != nil {
		return nil, err
	}
	checked, err := validateCertificate(certificate, this.now())
	if err != nil {
		return nil, err
	}
	leaf := checked.value.Leaf
	if this.validateKey != nil {
		if err := this.validateKey(leaf.PublicKey); err != nil {
			return nil, err
		}
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return nil, fmt.Errorf("issued ACME certificate identifiers differ from the requested DNS domain")
	}
	if !certificateRenewalAt(checked).After(this.now()) {
		return nil, fmt.Errorf("issued ACME certificate already requires renewal")
	}
	if err := this.store.putCertificate(ctx, domain, checked.value); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return checked.value, nil
}

func (this *ACME) acmeClient(ctx context.Context) (*acme.Client, error) {
	if this.client != nil {
		raw, err := this.store.read("account.pem")
		if err != nil {
			return nil, err
		}
		key, err := parseACMEAccountKey(raw)
		if err != nil {
			return nil, err
		}
		stored, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return nil, &materialError{"cannot inspect stored ACME account identity", err}
		}
		active, err := x509.MarshalPKIXPublicKey(this.client.Key.Public())
		if err != nil || !bytes.Equal(stored, active) {
			return nil, fmt.Errorf("stored ACME account key changed while the source was running")
		}
		return this.client, nil
	}
	key, err := this.store.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	if this.validateKey != nil {
		if err := this.validateKey(key.Public()); err != nil {
			return nil, err
		}
	}
	client := &acme.Client{
		Key: key, DirectoryURL: this.configuration.DirectoryUrl, HTTPClient: this.httpClient, UserAgent: "engity-bifroest",
		// Renewal scheduling owns retries and Retry-After; do not hide repeated
		// orders/429 responses inside a startup operation's network retries.
		RetryBackoff: func(int, *http.Request, *http.Response) time.Duration { return -1 },
	}
	account := &acme.Account{}
	if this.configuration.Email != "" {
		account.Contact = []string{"mailto:" + this.configuration.Email}
	}
	registered, err := client.Register(ctx, account, func(string) bool { return this.configuration.AcceptTerms })
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, &materialError{"ACME account registration failed", err}
	}
	if registered != nil && registered.Status != acme.StatusValid {
		return nil, fmt.Errorf("ACME account is not valid")
	}
	this.client = client
	return client, nil
}

func (this *ACME) issue(ctx context.Context, client *acme.Client, domain string, publish Challenge) (*tls.Certificate, error) {
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, &materialError{"ACME order creation failed", err}
	}
	if len(order.Identifiers) != 1 || order.Identifiers[0] != (acme.AuthzID{Type: "dns", Value: domain}) {
		return nil, fmt.Errorf("ACME order identifiers differ from the requested DNS domain")
	}
	if order.Status != acme.StatusReady && order.Status != acme.StatusPending {
		return nil, fmt.Errorf("ACME new order has an unexpected status")
	}
	if order.Status == acme.StatusPending {
		if len(order.AuthzURLs) == 0 {
			return nil, fmt.Errorf("ACME pending order has no authorizations")
		}
		for _, authorizationURL := range order.AuthzURLs {
			if err := fulfillACMEAuthorization(ctx, client, domain, authorizationURL, publish, this.now); err != nil {
				return nil, err
			}
		}
		order, err = client.WaitOrder(ctx, order.URI)
		if err != nil {
			return nil, &materialError{"ACME order authorization failed", err}
		}
	}
	if order.Status != acme.StatusReady {
		return nil, fmt.Errorf("ACME order is not ready for finalization")
	}
	if len(order.Identifiers) != 1 || order.Identifiers[0] != (acme.AuthzID{Type: "dns", Value: domain}) {
		return nil, fmt.Errorf("ACME ready order identifiers changed")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, key)
	if err != nil {
		return nil, &materialError{"cannot create ACME CSR", err}
	}
	chain, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return nil, &materialError{"ACME certificate issuance failed", err}
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key}, nil
}

func fulfillACMEAuthorization(ctx context.Context, client *acme.Client, domain, url string, publish Challenge, now func() time.Time) error {
	authorization, err := client.GetAuthorization(ctx, url)
	if err != nil {
		return &materialError{"cannot retrieve ACME authorization", err}
	}
	if authorization.Wildcard || authorization.Identifier != (acme.AuthzID{Type: "dns", Value: domain}) {
		return fmt.Errorf("ACME authorization identifier differs from the requested DNS domain")
	}
	if authorization.Status == acme.StatusValid {
		return nil
	}
	if authorization.Status != acme.StatusPending {
		return fmt.Errorf("ACME authorization is not pending or valid")
	}
	var selected *acme.Challenge
	for _, candidate := range authorization.Challenges {
		if candidate != nil && candidate.Type == "tls-alpn-01" {
			selected = candidate
			break
		}
	}
	if selected == nil {
		return fmt.Errorf("ACME authorization offers no TLS-ALPN-01 challenge")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	proof, err := client.TLSALPN01ChallengeCert(selected.Token, domain, acme.WithTemplate(&x509.Certificate{
		SerialNumber: serial, NotBefore: now().Add(-time.Hour), NotAfter: now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}))
	if err != nil {
		return &materialError{"cannot create TLS-ALPN-01 proof", err}
	}
	release, err := publish(&proof)
	if err != nil {
		return err
	}
	defer release()
	if _, err := client.Accept(ctx, selected); err != nil {
		return &materialError{"ACME challenge acceptance failed", err}
	}
	verified, err := client.WaitAuthorization(ctx, authorization.URI)
	if err != nil {
		return &materialError{"ACME challenge validation failed", err}
	}
	if verified.Status != acme.StatusValid || verified.Wildcard || verified.Identifier != (acme.AuthzID{Type: "dns", Value: domain}) {
		return fmt.Errorf("ACME verified authorization does not match its requested DNS domain")
	}
	return nil
}

func (this *ACME) Close() error {
	this.closeOnce.Do(func() {
		this.cancel()
		this.operation <- struct{}{}
		defer func() { <-this.operation }()
		this.httpClient.CloseIdleConnections()
		if err := this.store.close(); err != nil {
			this.closeErr = &materialError{"cannot close ACME storage", err}
		}
	})
	return this.closeErr
}

type httpsOnlyTransport struct{ http.RoundTripper }

func (this httpsOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil {
		return nil, fmt.Errorf("ACME endpoints must use HTTPS without credentials")
	}
	response, err := this.RoundTripper.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = &boundedACMEBody{ReadCloser: response.Body, remaining: maximumACMEStateBytes}
	return response, nil
}
func (this httpsOnlyTransport) CloseIdleConnections() {
	if closer, ok := this.RoundTripper.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

type boundedACMEBody struct {
	io.ReadCloser
	remaining int
}

func (this *boundedACMEBody) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if this.remaining == 0 {
		var probe [1]byte
		count, err := this.ReadCloser.Read(probe[:])
		if count != 0 {
			return 0, fmt.Errorf("ACME response exceeds its size limit")
		}
		return 0, err
	}
	if len(buffer) > this.remaining {
		buffer = buffer[:this.remaining]
	}
	count, err := this.ReadCloser.Read(buffer)
	this.remaining -= count
	return count, err
}
