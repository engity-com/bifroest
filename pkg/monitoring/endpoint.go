// Package monitoring provides a separate, read-only operational HTTP listener.
package monitoring

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

type Endpoint struct {
	server    *http.Server
	addresses configuration.Monitoring
	ready     atomic.Bool
	allowed   []netip.Prefix
	token     [sha256.Size]byte
	hasToken  bool
	metrics   http.Handler
	listeners []net.Listener
	wait      sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
	lifecycle sync.Mutex
	started   bool
	closed    bool
	tls       *transporttls.TLS
	cancelTLS context.CancelFunc
}

type Options struct {
	// The service installs a shared binding after verifying all key purposes.
	DeferTLS bool
}

// New prepares monitoring only when enabled. The service defers TLS to install a
// shared, purpose-checked binding. No default HTTP mux or global registry is used.
func New(conf *configuration.Monitoring, gatherer prometheus.Gatherer, options ...Options) (*Endpoint, error) {
	if !conf.IsEnabled() {
		return nil, nil
	}
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	if gatherer == nil {
		return nil, fmt.Errorf("monitoring requires a metrics registry")
	}
	result := &Endpoint{addresses: *conf, metrics: promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{EnableOpenMetrics: true, MaxRequestsInFlight: 4, Timeout: 5 * time.Second})}
	for _, value := range conf.AllowedRemoteHosts {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, parseErr := netip.ParseAddr(value)
			if parseErr != nil {
				return nil, fmt.Errorf("invalid monitoring peer filter")
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		result.allowed = append(result.allowed, prefix)
	}
	token := conf.BearerToken
	if conf.BearerTokenFile != "" {
		info, err := os.Stat(conf.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect monitoring bearer token file: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 4098 {
			return nil, fmt.Errorf("monitoring bearer token must be a bounded regular file")
		}
		file, err := os.Open(conf.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("cannot open monitoring bearer token file: %w", err)
		}
		opened, err := file.Stat()
		if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			_ = file.Close()
			return nil, fmt.Errorf("monitoring bearer token file changed while opening")
		}
		content, readErr := io.ReadAll(io.LimitReader(file, 4099))
		if err := errors.Join(readErr, file.Close()); err != nil {
			return nil, fmt.Errorf("cannot read monitoring bearer token file: %w", err)
		}
		token = strings.TrimRight(string(content), "\r\n")
		if !configuration.ValidMonitoringBearerToken(token) || len(content) > 4098 {
			return nil, fmt.Errorf("invalid monitoring bearer token file content")
		}
	}
	if token != "" {
		result.hasToken = true
		result.token = sha256.Sum256([]byte(token))
	}
	result.server = &http.Server{Handler: result, ReadHeaderTimeout: conf.ReadHeaderTimeout.Native(), ReadTimeout: conf.ReadHeaderTimeout.Native(),
		WriteTimeout: 10 * time.Second, IdleTimeout: conf.IdleTimeout.Native(), MaxHeaderBytes: int(conf.MaxHeaderBytes)}
	deferred := len(options) != 0 && options[0].DeferTLS
	if conf.Tls.IsEnabled() && !deferred {
		profile, err := conf.Tls.ServerDefinition()
		if err != nil {
			return nil, err
		}
		manager, err := transporttls.NewManaged(transporttls.Config{Profile: profile, Names: conf.Domains,
			StartupTimeout: configuration.DefaultHttpStartupTimeout.Native()}, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot load monitoring TLS certificate/key: %w", err)
		}
		result.tls = manager
		binding, err := manager.Bind(conf.Domains, []string{"h2", "http/1.1"}, len(conf.Domains) == 1)
		if err != nil {
			_ = manager.Close()
			return nil, err
		}
		if err := manager.Prepare(context.Background()); err != nil {
			_ = manager.Close()
			return nil, err
		}
		result.server.TLSConfig = binding.Config()
	}
	return result, nil
}

// SetTLSConfig is only valid before Start; ownership stays with the service.
func (this *Endpoint) SetTLSConfig(config *tls.Config) error {
	this.lifecycle.Lock()
	defer this.lifecycle.Unlock()
	if this.started || this.closed || config == nil {
		return fmt.Errorf("cannot install monitoring TLS configuration")
	}
	this.server.TLSConfig = config
	return nil
}

// ValidateKeys checks purpose separation before the TLS listener is published.
func (this *Endpoint) ValidateKeys(validate func(crypto.PublicKey) error) error {
	if this == nil || this.server.TLSConfig == nil {
		return nil
	}
	if this.tls != nil {
		return this.tls.ValidateKeys(validate)
	}
	for _, certificate := range this.server.TLSConfig.Certificates {
		if err := validate(certificate.Leaf.PublicKey); err != nil {
			return err
		}
	}
	return nil
}

// Start binds every address before serving any of them. onError reports an
// unexpected monitoring failure without changing access or audit policy.
func (this *Endpoint) Start(onError func(error)) error {
	if this == nil {
		return nil
	}
	this.lifecycle.Lock()
	defer this.lifecycle.Unlock()
	if this.closed {
		return fmt.Errorf("monitoring endpoint is closed")
	}
	if this.started {
		return nil
	}
	if this.addresses.Tls.IsEnabled() && this.server.TLSConfig == nil {
		return fmt.Errorf("monitoring TLS binding has not been installed")
	}
	for _, address := range this.addresses.Addresses {
		listener, err := address.Listen()
		if err != nil {
			for _, previous := range this.listeners {
				_ = previous.Close()
			}
			this.closed = true
			return fmt.Errorf("cannot bind monitoring listener: %w", err)
		}
		this.listeners = append(this.listeners, listener)
	}
	this.started = true
	if this.tls != nil {
		ctx, cancel := context.WithCancel(context.Background())
		this.cancelTLS = cancel
		this.wait.Add(1)
		go func() { defer this.wait.Done(); _ = this.tls.RunFileReload(ctx, onError) }()
	}
	for _, listener := range this.listeners {
		this.wait.Add(1)
		go func() {
			defer this.wait.Done()
			var err error
			if this.server.TLSConfig != nil {
				err = this.server.ServeTLS(listener, "", "")
			} else {
				err = this.server.Serve(listener)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && onError != nil {
				onError(err)
			}
		}()
	}
	return nil
}

func (this *Endpoint) SetReady(ready bool) {
	if this != nil {
		this.ready.Store(ready)
	}
}
func (this *Endpoint) Ready() bool { return this != nil && this.ready.Load() }

func (this *Endpoint) Close() error {
	if this == nil {
		return nil
	}
	this.closeOnce.Do(func() {
		this.lifecycle.Lock()
		this.closed = true
		this.lifecycle.Unlock()
		this.SetReady(false)
		if this.cancelTLS != nil {
			this.cancelTLS()
		}
		if this.tls != nil {
			this.closeErr = errors.Join(this.closeErr, this.tls.Close())
		}
		ctx, cancel := context.WithTimeout(context.Background(), this.addresses.GracefulShutdownTimeout.Native())
		defer cancel()
		this.closeErr = errors.Join(this.closeErr, this.server.Shutdown(ctx))
		if this.closeErr != nil {
			this.closeErr = errors.Join(this.closeErr, this.server.Close())
		}
		for _, listener := range this.listeners {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				this.closeErr = errors.Join(this.closeErr, err)
			}
		}
		this.wait.Wait()
	})
	return this.closeErr
}

func (this *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !this.allows(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/status", "/ready", "/metrics":
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/status":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	case "/ready":
		if !this.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ready\n")
	case "/metrics":
		if this.hasToken {
			values := r.Header.Values("Authorization")
			var token string
			if len(values) == 1 {
				scheme, value, ok := strings.Cut(values[0], " ")
				if ok && strings.EqualFold(scheme, "Bearer") {
					token = value
				}
			}
			candidate := sha256.Sum256([]byte(token))
			if subtle.ConstantTimeCompare(candidate[:], this.token[:]) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		this.metrics.ServeHTTP(&metricsResponseWriter{ResponseWriter: w}, r)
	}
}

// Scrape errors must not disclose internal collector error text or file paths.
type metricsResponseWriter struct {
	http.ResponseWriter
	failed bool
}

func (this *metricsResponseWriter) Unwrap() http.ResponseWriter { return this.ResponseWriter }
func (this *metricsResponseWriter) WriteHeader(status int) {
	if this.failed {
		return
	}
	if status >= 500 {
		this.failed = true
		this.Header().Del("Content-Encoding")
		this.Header().Del("Content-Length")
		this.Header().Set("Content-Type", "text/plain; charset=utf-8")
		this.ResponseWriter.WriteHeader(status)
		_, _ = io.WriteString(this.ResponseWriter, "metrics unavailable\n")
		return
	}
	this.ResponseWriter.WriteHeader(status)
}
func (this *metricsResponseWriter) Write(data []byte) (int, error) {
	if this.failed {
		return len(data), nil
	}
	return this.ResponseWriter.Write(data)
}

func (this *Endpoint) allows(remote string) bool {
	if len(this.allowed) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	address = address.WithZone("").Unmap()
	for _, prefix := range this.allowed {
		if prefix.Contains(address) || address.Is4() && prefix.Addr().Is4In6() && prefix.Contains(netip.AddrFrom16(address.As16())) {
			return true
		}
	}
	return false
}
