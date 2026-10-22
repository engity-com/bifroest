package https

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

// KeyValidator checks public key separation before TLS readiness/publication.
// The built-in ACME backend also checks before requests and persistence; custom
// Sources own their storage policy. Errors must be log-safe and calls concurrent-safe.
type KeyValidator func(crypto.PublicKey) error

type EndpointOptions struct {
	Handler     http.Handler
	Source      CertificateSource
	ValidateKey KeyValidator
}

// Endpoint serves already-bound listeners. The caller must bind every SSH and
// HTTPS input before serving challenges, call Prepare, and own the renewal loop.
type Endpoint struct {
	tls       *TLS
	source    *lazyACME
	server    *http.Server
	grace     time.Duration
	closeOnce sync.Once
	closeErr  error
}

func NewEndpoint(conf *configuration.Http, options EndpointOptions) (*Endpoint, error) {
	var lazy *lazyACME
	source := options.Source
	if conf.IsEnabled() && conf.Tls.Acme.Enabled && source == nil {
		copyOfConf := *conf
		lazy = &lazyACME{configuration: copyOfConf, validateKey: options.ValidateKey}
		source = lazy
	}
	manager, err := NewTLS(conf, source)
	if err != nil {
		return nil, err
	}
	manager.validateKey = options.ValidateKey
	for _, certificate := range manager.explicit {
		if options.ValidateKey != nil {
			if err := options.ValidateKey(certificate.value.Leaf.PublicKey); err != nil {
				_ = manager.Close()
				return nil, err
			}
		}
	}
	handler := options.Handler
	if handler == nil {
		handler = http.HandlerFunc(unimplementedBrowserHandler)
	}
	boundary, err := Boundary(conf.Domains, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !manager.Ready() {
			http.Error(w, "HTTPS is not ready", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	if err != nil {
		_ = manager.Close()
		return nil, err
	}
	endpoint := &Endpoint{tls: manager, source: lazy, grace: conf.GracefulShutdownTimeout.Native()}
	endpoint.server = &http.Server{
		TLSConfig: manager.Config(), Handler: boundary,
		ReadHeaderTimeout: conf.ReadHeaderTimeout.Native(), ReadTimeout: conf.ReadHeaderTimeout.Native(), IdleTimeout: conf.IdleTimeout.Native(), MaxHeaderBytes: int(conf.MaxHeaderBytes),
		// Never log attacker-controlled handshake diagnostics or private causes.
		ErrorLog: log.New(discardHTTPDiagnostics{}, "", 0),
	}
	return endpoint, nil
}

func (this *Endpoint) Prepare(ctx context.Context) error { return this.tls.Prepare(ctx) }
func (this *Endpoint) Ready() bool                       { return this.tls.Ready() }
func (this *Endpoint) Serve(listener net.Listener) error {
	return this.server.ServeTLS(listener, "", "")
}
func (this *Endpoint) RunRenewal(ctx context.Context, onFailure func(error)) error {
	return this.tls.RunRenewal(ctx, onFailure)
}

// Shutdown stops acquisition and new handshakes immediately, then bounds HTTP
// draining independently of SSH's grace period. Serve loops are drained by caller.
func (this *Endpoint) Shutdown() error {
	_ = this.tls.Close()
	ctx, cancel := context.WithTimeout(context.Background(), this.grace)
	defer cancel()
	err := this.server.Shutdown(ctx)
	closeErr := this.server.Close()
	if errors.Is(err, context.DeadlineExceeded) {
		err = nil
	}
	return errors.Join(err, closeErr)
}

func (this *Endpoint) Close() error {
	this.closeOnce.Do(func() {
		this.closeErr = this.Shutdown()
		if this.source != nil {
			this.closeErr = errors.Join(this.closeErr, this.source.Close())
		}
	})
	return this.closeErr
}

func unimplementedBrowserHandler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/_bifroest/") {
		http.NotFound(w, r)
		return
	}
	if _, err := bnet.HttpSlugFromURL(r.URL); err != nil {
		http.Error(w, "invalid flow path", http.StatusBadRequest)
		return
	}
	http.Error(w, "Browser access is not implemented yet.", http.StatusNotImplemented)
}

type discardHTTPDiagnostics struct{}

func (discardHTTPDiagnostics) Write(value []byte) (int, error) { return len(value), nil }

type lazyACME struct {
	configuration configuration.Http
	validateKey   KeyValidator
	mutex         sync.Mutex
	value         *ACME
	closed        bool
}

func (this *lazyACME) get() (*ACME, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return nil, ErrClosed
	}
	if this.value == nil {
		value, err := NewACME(&this.configuration)
		if err != nil {
			return nil, err
		}
		value.validateKey = this.validateKey
		value.store.validateKey = this.validateKey
		this.value = value
	}
	return this.value, nil
}
func (this *lazyACME) Certificate(ctx context.Context, domain string, challenge Challenge) (*tls.Certificate, error) {
	value, err := this.get()
	if err != nil {
		return nil, err
	}
	return value.Certificate(ctx, domain, challenge)
}
func (this *lazyACME) Renew(ctx context.Context, domain string, challenge Challenge) (*tls.Certificate, error) {
	value, err := this.get()
	if err != nil {
		return nil, err
	}
	return value.Renew(ctx, domain, challenge)
}
func (this *lazyACME) Close() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.closed = true
	if this.value != nil {
		return this.value.Close()
	}
	return nil
}
