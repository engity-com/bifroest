package https

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

type EndpointOptions struct {
	Handler           http.Handler
	Source            CertificateSource
	ValidateKey       KeyValidator
	ObserveRequest    func(http.Handler) http.Handler
	ObserveConnection func() ConnectionObservation
	ObserveRejection  func(*http.Request, string)
	ValidateFiles     func() error
	Binding           *transporttls.Binding
	Challenges        *transporttls.Registry
}

// Endpoint serves already-bound listeners. The caller must bind every SSH and
// HTTPS input before serving challenges, call Prepare, and own TLS maintenance.
type Endpoint struct {
	tls               *TLS
	binding           *transporttls.Binding
	server            *http.Server
	grace             time.Duration
	closeOnce         sync.Once
	closeErr          error
	observeConnection func() ConnectionObservation
	plainReady        atomic.Bool
	closed            atomic.Bool
	done              chan struct{}
}

func NewEndpoint(conf *configuration.Http, options EndpointOptions) (*Endpoint, error) {
	if conf == nil || !conf.IsEnabled() {
		return nil, fmt.Errorf("HTTP is disabled")
	}
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	if !conf.Tls.IsEnabled() && options.Binding != nil {
		return nil, fmt.Errorf("disabled HTTP TLS cannot use a server binding")
	}
	var manager *TLS
	var err error
	binding := options.Binding
	if conf.Tls.IsEnabled() && binding == nil {
		adapted, adaptErr := tlsConfiguration(conf)
		if adaptErr != nil {
			return nil, adaptErr
		}
		adapted.ValidateKey, adapted.ValidateFiles = options.ValidateKey, options.ValidateFiles
		manager, err = transporttls.NewManaged(adapted, options.Source)
		if err != nil {
			return nil, err
		}
		binding, err = manager.Bind(conf.Domains, []string{"h2", "http/1.1"}, false)
		if err != nil {
			_ = manager.Close()
			return nil, err
		}
	}
	handler := options.Handler
	if handler == nil {
		handler = http.HandlerFunc(unimplementedBrowserHandler)
	}
	endpoint := &Endpoint{tls: manager, binding: binding, grace: conf.GracefulShutdownTimeout.Native(), observeConnection: options.ObserveConnection, done: make(chan struct{})}
	boundary, err := httpBoundary(conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !endpoint.Ready() {
			http.Error(w, "HTTPS is not ready", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}), conf.SshTunnel.IsEnabled(), options.ObserveRejection)
	if err != nil {
		if manager != nil {
			_ = manager.Close()
		}
		return nil, err
	}
	if options.ObserveRequest != nil {
		boundary = options.ObserveRequest(boundary)
	}
	endpoint.server = &http.Server{
		Handler:           boundary,
		ReadHeaderTimeout: conf.ReadHeaderTimeout.Native(), ReadTimeout: conf.ReadHeaderTimeout.Native(), IdleTimeout: conf.IdleTimeout.Native(), MaxHeaderBytes: int(conf.MaxHeaderBytes),
		// Never log attacker-controlled handshake diagnostics or private causes.
		ErrorLog:  log.New(discardHTTPDiagnostics{}, "", 0),
		ConnState: observeConnectionState,
	}
	if binding != nil {
		challenges := options.Challenges
		if challenges == nil {
			challenges = &transporttls.Registry{}
			if manager != nil {
				if err := challenges.Register(manager); err != nil {
					_ = manager.Close()
					return nil, err
				}
			}
		}
		endpoint.server.TLSConfig = challenges.Config(binding.Config())
	}
	return endpoint, nil
}

func (this *Endpoint) Prepare(ctx context.Context) error {
	if this.binding == nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		if this.closed.Load() {
			return ErrClosed
		}
		this.plainReady.Store(true)
		return nil
	}
	return this.binding.Prepare(ctx)
}
func (this *Endpoint) Ready() bool {
	return !this.closed.Load() && (this.binding != nil && this.binding.Ready() || this.binding == nil && this.plainReady.Load())
}
func (this *Endpoint) Serve(listener net.Listener) error {
	if this.observeConnection != nil {
		listener = observedListener{Listener: listener, observe: this.observeConnection}
	}
	if this.binding == nil {
		return this.server.Serve(listener)
	}
	return this.server.ServeTLS(listener, "", "")
}

// CertificateExpirations snapshots only published, configured certificates.
func (this *Endpoint) CertificateExpirations() map[string]time.Time {
	if this.binding == nil {
		return nil
	}
	return this.binding.Expirations()
}
func (this *Endpoint) RunFileReload(ctx context.Context, onFailure func(error)) error {
	if this.tls == nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-this.done:
			return ErrClosed
		}
	}
	return this.tls.RunFileReload(ctx, onFailure)
}

// RenewDue lets the owner schedule maintenance for a standalone endpoint.
// Externally supplied bindings are maintained through their shared TLS manager.
func (this *Endpoint) RenewDue(ctx context.Context) error {
	if this.closed.Load() {
		return ErrClosed
	}
	if this.tls == nil {
		return ctx.Err()
	}
	return this.tls.RenewDue(ctx)
}

// Shutdown stops acquisition and new handshakes immediately, then bounds HTTP
// draining independently of SSH's grace period. Serve loops are drained by caller.
func (this *Endpoint) Shutdown() error {
	if !this.closed.Swap(true) {
		close(this.done)
	}
	if this.tls != nil {
		_ = this.tls.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), this.grace)
	defer cancel()
	err := this.server.Shutdown(ctx)
	closeErr := this.server.Close()
	if ctx.Err() == context.DeadlineExceeded && onlyShutdownCause(err, context.DeadlineExceeded) || onlyShutdownCause(err, net.ErrClosed) {
		err = nil
	}
	if onlyShutdownCause(closeErr, net.ErrClosed) {
		closeErr = nil
	}
	return errors.Join(err, closeErr)
}

// The joint listener owner can stop accepting before net/http closes its own
// listener wrapper. Only an exclusively benign cause is ignored: errors.Is on
// a joined error would also hide an independent cleanup failure.
func onlyShutdownCause(err, target error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		found := false
		for _, cause := range joined.Unwrap() {
			if cause == nil {
				continue
			}
			if !onlyShutdownCause(cause, target) {
				return false
			}
			found = true
		}
		return found
	}
	if cause := errors.Unwrap(err); cause != nil {
		return onlyShutdownCause(cause, target)
	}
	return err == target
}

func (this *Endpoint) Close() error {
	this.closeOnce.Do(func() {
		this.closeErr = this.Shutdown()
	})
	return this.closeErr
}

func unimplementedBrowserHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/_bifroest/") {
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
