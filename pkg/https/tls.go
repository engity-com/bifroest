package https

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/configuration"
)

var (
	ErrNotReady = errors.New("HTTPS certificates are not ready")
	ErrClosed   = errors.New("HTTPS certificate preparation is closed")
)

// Challenge installs a temporary TLS-ALPN-01 proof for the currently requested
// domain. Its release function must be called; cancellation also removes it.
type Challenge func(*tls.Certificate) (release func(), err error)

// CertificateSource is the context-bound boundary for cached/issued ACME
// certificates. Implementations must honor ctx and not mutate returned keys.
// Returned errors must be safe for server logs, without private material.
// No source is invoked in response to an arbitrary incoming ClientHello.
type CertificateSource interface {
	Certificate(ctx context.Context, domain string, challenge Challenge) (*tls.Certificate, error)
}

type activeChallenge struct {
	certificate *tls.Certificate
	context     context.Context
}

// TLS owns the all-domain readiness barrier and ephemeral ALPN proofs. It does
// not open listeners or start renewal goroutines; its caller owns those lifetimes.
type TLS struct {
	domains        []string
	explicit       map[string]*preparedCertificate
	source         CertificateSource
	validateKey    KeyValidator
	startupTimeout time.Duration
	now            func() time.Time
	lifetime       context.Context
	cancel         context.CancelFunc
	preparing      chan struct{}
	renewing       chan struct{}
	renewRetry     map[string]time.Time
	mutex          sync.RWMutex
	ready          bool
	closed         bool
	activeDomain   string
	certificates   map[string]*preparedCertificate
	challenges     map[string]*activeChallenge
}

func NewTLS(conf *configuration.Http, source CertificateSource) (*TLS, error) {
	return newTLS(conf, source, time.Now)
}

func newTLS(conf *configuration.Http, source CertificateSource, now func() time.Time) (*TLS, error) {
	if !conf.IsEnabled() {
		return nil, fmt.Errorf("HTTP is disabled")
	}
	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid HTTP configuration: %w", err)
	}
	domains, err := conf.Domains.Canonical()
	if err != nil {
		return nil, err
	}
	explicit := make(map[string]*preparedCertificate)
	for index, configured := range conf.Tls.Certificates {
		certificate, err := loadCertificate(configured, now())
		if err != nil {
			return nil, fmt.Errorf("[http][tls][certificates][%d] %w", index, err)
		}
		matched := false
		for _, domain := range domains {
			if !certificateMatches(certificate.value, domain) {
				continue
			}
			matched = true
			if explicit[domain] == nil {
				explicit[domain] = certificate
			}
		}
		if !matched {
			return nil, fmt.Errorf("[http][tls][certificates][%d] covers no configured domain", index)
		}
	}
	if !conf.Tls.Acme.Enabled {
		source = nil
	}
	for _, domain := range domains {
		if explicit[domain] == nil && source == nil {
			return nil, fmt.Errorf("[http][tls] no certificate source covers configured domain %q", domain)
		}
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &TLS{
		domains: domains, explicit: explicit, source: source, startupTimeout: conf.StartupTimeout.Native(), now: now,
		lifetime: lifetime, cancel: cancel, challenges: make(map[string]*activeChallenge), preparing: make(chan struct{}, 1),
		renewing: make(chan struct{}, 1), renewRetry: make(map[string]time.Time),
	}, nil
}

// Prepare only publishes a complete, valid set. Until then normal TLS handshakes
// fail, while an actively installed ACME proof remains available via ALPN.
func (this *TLS) Prepare(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, this.startupTimeout)
	stopClose := context.AfterFunc(this.lifetime, cancel)
	defer stopClose()
	defer cancel()
	select {
	case <-this.lifetime.Done():
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case this.preparing <- struct{}{}:
		defer func() { <-this.preparing }()
	}
	this.mutex.RLock()
	if this.closed {
		this.mutex.RUnlock()
		return ErrClosed
	}
	if this.ready {
		for domain, certificate := range this.certificates {
			if !certificate.validAt(this.now()) {
				this.mutex.RUnlock()
				return fmt.Errorf("TLS certificate for %q is no longer valid", domain)
			}
		}
		this.mutex.RUnlock()
		return ctx.Err()
	}
	this.mutex.RUnlock()
	certificates := make(map[string]*preparedCertificate, len(this.domains))
	for _, domain := range this.domains {
		if err := ctx.Err(); err != nil {
			return err
		}
		var candidate *tls.Certificate
		if explicit := this.explicit[domain]; explicit != nil {
			candidate = explicit.value
		}
		if candidate == nil {
			this.mutex.Lock()
			if this.closed {
				this.mutex.Unlock()
				return ErrClosed
			}
			if err := ctx.Err(); err != nil {
				this.mutex.Unlock()
				return err
			}
			this.activeDomain = domain
			this.mutex.Unlock()
			var err error
			candidate, err = this.source.Certificate(ctx, domain, func(certificate *tls.Certificate) (func(), error) {
				return this.installChallenge(ctx, domain, certificate)
			})
			this.mutex.Lock()
			this.activeDomain = ""
			delete(this.challenges, domain)
			this.mutex.Unlock()
			if err != nil {
				return fmt.Errorf("cannot prepare TLS certificate for %q: %w", domain, err)
			}
		}
		checked, err := validateCertificate(candidate, this.now())
		if err != nil {
			return fmt.Errorf("invalid TLS certificate for %q: %w", domain, err)
		}
		if !certificateMatches(checked.value, domain) {
			return fmt.Errorf("TLS certificate does not cover configured domain %q", domain)
		}
		if this.validateKey != nil {
			if err := this.validateKey(checked.value.Leaf.PublicKey); err != nil {
				return err
			}
		}
		certificates[domain] = checked
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// A slow later domain must not publish an already expired earlier one.
	for domain, certificate := range certificates {
		if !certificate.validAt(this.now()) {
			return fmt.Errorf("TLS certificate for %q expired before readiness", domain)
		}
	}
	this.certificates, this.ready = certificates, true
	return nil
}

func (this *TLS) Ready() bool {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	if !this.ready || this.closed {
		return false
	}
	for _, certificate := range this.certificates {
		if !certificate.validAt(this.now()) {
			return false
		}
	}
	return true
}

func (this *TLS) Close() error {
	this.mutex.Lock()
	this.closed, this.ready = true, false
	this.certificates = nil
	clear(this.challenges)
	this.mutex.Unlock()
	this.cancel()
	return nil
}

func (this *TLS) Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true, GetConfigForClient: this.configForClient}
}

func (this *TLS) configForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello == nil {
		return nil, fmt.Errorf("missing TLS ClientHello")
	}
	name := hello.ServerName
	// Browsers omit SNI for IP URLs. Only a sole explicitly configured IP may
	// be selected without SNI; never guess a DNS name or one of several domains.
	if name == "" && len(this.domains) == 1 {
		if _, err := netip.ParseAddr(this.domains[0]); err == nil {
			name = this.domains[0]
		}
		if len(this.domains[0]) > 2 && this.domains[0][0] == '[' {
			if _, err := netip.ParseAddr(this.domains[0][1 : len(this.domains[0])-1]); err == nil {
				name = this.domains[0]
			}
		}
	}
	canonical, err := (configuration.HttpDomains{name}).Canonical()
	if err != nil || len(canonical) != 1 || !slices.Contains(this.domains, canonical[0]) {
		return nil, fmt.Errorf("TLS server name is not configured")
	}
	name = canonical[0]
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	if this.closed {
		return nil, ErrClosed
	}
	if slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
		if len(hello.SupportedProtos) != 1 {
			return nil, fmt.Errorf("ACME ALPN must not be mixed with application protocols")
		}
		challenge := this.challenges[name]
		if challenge == nil || challenge.context.Err() != nil || !validAt(challenge.certificate.Leaf, this.now()) {
			return nil, fmt.Errorf("no active TLS-ALPN-01 proof")
		}
		return handshakeConfig(challenge.certificate, []string{acme.ALPNProto}), nil
	}
	if !this.ready {
		return nil, ErrNotReady
	}
	certificate := this.certificates[name]
	if !certificate.validAt(this.now()) {
		return nil, fmt.Errorf("TLS certificate is no longer valid")
	}
	return handshakeConfig(certificate.value, []string{"h2", "http/1.1"}), nil
}

func handshakeConfig(certificate *tls.Certificate, protocols []string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true, Certificates: []tls.Certificate{*certificate}, NextProtos: protocols}
}

func validAt(certificate *x509.Certificate, now time.Time) bool {
	return certificate != nil && !now.Before(certificate.NotBefore) && now.Before(certificate.NotAfter)
}

func (this *TLS) installChallenge(ctx context.Context, domain string, certificate *tls.Certificate) (func(), error) {
	checked, err := validateChallenge(certificate, domain, this.now())
	if err != nil {
		return nil, err
	}
	this.mutex.Lock()
	if this.closed || ctx.Err() != nil || this.activeDomain != domain {
		this.mutex.Unlock()
		return nil, fmt.Errorf("TLS-ALPN-01 proof is outside its active issuance")
	}
	challenge := &activeChallenge{certificate: checked, context: ctx}
	this.challenges[domain] = challenge
	this.mutex.Unlock()
	release := func() {
		this.mutex.Lock()
		if this.challenges[domain] == challenge {
			delete(this.challenges, domain)
		}
		this.mutex.Unlock()
	}
	stop := context.AfterFunc(ctx, release)
	return func() { stop(); release() }, nil
}

func validateChallenge(certificate *tls.Certificate, domain string, now time.Time) (*tls.Certificate, error) {
	if certificate == nil || len(certificate.Certificate) != 1 || len(certificate.Certificate[0]) > maximumCertificateFileBytes {
		return nil, fmt.Errorf("invalid TLS-ALPN-01 proof certificate")
	}
	// ACME's critical identifier extension is intentionally not an ordinary
	// server-auth certificate: check it separately, never publish it as one.
	copyOfCertificate := *certificate
	copyOfCertificate.Certificate = [][]byte{slices.Clone(certificate.Certificate[0])}
	leaf, err := x509.ParseCertificate(copyOfCertificate.Certificate[0])
	if err != nil || !validAt(leaf, now) || leaf.IsCA || !certificateMatches(&tls.Certificate{Leaf: leaf}, domain) {
		return nil, fmt.Errorf("invalid TLS-ALPN-01 proof identity or lifetime")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return nil, fmt.Errorf("TLS-ALPN-01 proof must name only the requested DNS domain")
	}
	identifier := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
	if len(leaf.UnhandledCriticalExtensions) != 1 || !leaf.UnhandledCriticalExtensions[0].Equal(identifier) {
		return nil, fmt.Errorf("TLS-ALPN-01 proof must have only its critical identifier extension")
	}
	found := false
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(identifier) {
			continue
		}
		var digest []byte
		rest, err := asn1.Unmarshal(extension.Value, &digest)
		if found || !extension.Critical || err != nil || len(rest) != 0 || len(digest) != 32 {
			return nil, fmt.Errorf("invalid TLS-ALPN-01 identifier extension")
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("missing TLS-ALPN-01 identifier extension")
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return nil, fmt.Errorf("invalid TLS-ALPN-01 self-signature")
	}
	// Let crypto/tls validate key compatibility without accepting an untrusted Leaf.
	public, err := certificateSigner(certificate.PrivateKey)
	if err != nil {
		return nil, err
	}
	key, err := x509.MarshalPKIXPublicKey(public.Public())
	if err != nil || !slices.Equal(key, leaf.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("TLS-ALPN-01 proof key mismatch")
	}
	copyOfCertificate.Leaf = leaf
	return &copyOfCertificate, nil
}
