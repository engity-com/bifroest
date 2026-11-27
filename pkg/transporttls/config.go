package transporttls

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// KeyValidator must be concurrent-safe; errors must not contain key material.
type KeyValidator func(crypto.PublicKey) error

type Config struct {
	Profile        configuration.Tls
	Names          configuration.ServerNames
	StartupTimeout time.Duration
	NextProtos     []string
	ValidateKey    KeyValidator
	ValidateFiles  func() error
}

func (this Config) Validate() error {
	if err := this.Profile.Validate(); err != nil {
		return err
	}
	if this.StartupTimeout <= 0 {
		return fmt.Errorf("TLS startup timeout must be positive")
	}
	if len(this.Names) == 0 {
		return fmt.Errorf("TLS requires explicit server names")
	}
	return this.Names.Validate()
}

// ValidateKeys is called before publishing a consumer, never during handshakes.
func (this *TLS) ValidateKeys(validate KeyValidator) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	for _, certificate := range this.explicit {
		if err := validate(certificate.value.Leaf.PublicKey); err != nil {
			return err
		}
	}
	this.validateKey = validate
	return nil
}

// NewManaged lazily opens ACME only if preparation actually needs a certificate.
// Close cancels and drains its source; no constructor starts background work.
func NewManaged(conf Config, source CertificateSource) (*TLS, error) {
	conf.Names = slices.Clone(conf.Names)
	conf.NextProtos = slices.Clone(conf.NextProtos)
	conf.Profile.Certificates = slices.Clone(conf.Profile.Certificates)
	if conf.Profile.Acme != nil {
		automation := *conf.Profile.Acme
		conf.Profile.Acme = &automation
	}
	checkFiles := func() error {
		if len(conf.Profile.Certificates) != 0 && conf.ValidateFiles != nil && conf.ValidateFiles() != nil {
			return fmt.Errorf("TLS certificate path safety check failed (details redacted)")
		}
		return nil
	}
	if err := checkFiles(); err != nil {
		return nil, err
	}
	var lazy *lazyACME
	if source == nil && conf.Profile.Acme.IsEnabled() {
		lazy = &lazyACME{configuration: conf}
		source = lazy
	}
	manager, err := New(conf, source)
	if err != nil {
		return nil, err
	}
	manager.ownedSource = lazy
	if err := checkFiles(); err != nil {
		_ = manager.Close()
		return nil, err
	}
	for _, certificate := range manager.explicit {
		if conf.ValidateKey != nil {
			if err := conf.ValidateKey(certificate.value.Leaf.PublicKey); err != nil {
				_ = manager.Close()
				return nil, err
			}
		}
	}
	return manager, nil
}

type lazyACME struct {
	configuration Config
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
		value, err := NewACMESource(this.configuration)
		if err != nil {
			return nil, err
		}
		value.store.validateKey = this.configuration.ValidateKey
		this.value = value
	}
	return this.value, nil
}
func (this *lazyACME) Certificate(ctx context.Context, name string, challenge Challenge) (*tls.Certificate, error) {
	value, err := this.get()
	if err != nil {
		return nil, err
	}
	return value.Certificate(ctx, name, challenge)
}
func (this *lazyACME) Renew(ctx context.Context, name string, challenge Challenge) (*tls.Certificate, error) {
	value, err := this.get()
	if err != nil {
		return nil, err
	}
	return value.Renew(ctx, name, challenge)
}
func (this *lazyACME) Close() error {
	this.mutex.Lock()
	this.closed = true
	value := this.value
	this.mutex.Unlock()
	if value != nil {
		return value.Close()
	}
	return nil
}

// Expirations returns a copy, including the effective chain deadline.
func (this *TLS) Expirations() map[string]time.Time {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	result := make(map[string]time.Time, len(this.certificates))
	for name, certificate := range this.certificates {
		result[name] = certificate.notAfter
	}
	return result
}

// Binding restricts an immutable source to one consumer. It owns no source,
// listener or maintenance loop, and cannot expand the manager's registered names.
type Binding struct {
	manager    *TLS
	names      []string
	protocols  []string
	withoutSNI bool
}

func (this *TLS) Bind(names configuration.ServerNames, protocols []string, withoutSNI bool) (*Binding, error) {
	canonical, err := names.Canonical()
	if err != nil || len(canonical) == 0 {
		return nil, fmt.Errorf("TLS binding requires explicit valid names")
	}
	for _, name := range canonical {
		if !slices.Contains(this.domains, name) {
			return nil, fmt.Errorf("TLS binding name is not registered")
		}
	}
	if withoutSNI && len(canonical) != 1 {
		return nil, fmt.Errorf("TLS binding without SNI requires exactly one identity")
	}
	return &Binding{manager: this, names: canonical, protocols: slices.Clone(protocols), withoutSNI: withoutSNI}, nil
}
func (this *Binding) Prepare(ctx context.Context) error { return this.manager.Prepare(ctx) }
func (this *Binding) Ready() bool {
	this.manager.mutex.RLock()
	defer this.manager.mutex.RUnlock()
	if this.manager.closed || !this.manager.ready {
		return false
	}
	for _, name := range this.names {
		if !this.manager.certificates[name].validAt(this.manager.now()) {
			return false
		}
	}
	return true
}
func (this *Binding) Expirations() map[string]time.Time {
	snapshot := this.manager.Expirations()
	for name := range snapshot {
		if !slices.Contains(this.names, name) {
			delete(snapshot, name)
		}
	}
	return snapshot
}
func (this *Binding) Config() *tls.Config {
	return &tls.Config{MinVersion: this.manager.minVersion, SessionTicketsDisabled: true, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello == nil {
			return nil, fmt.Errorf("missing TLS ClientHello")
		}
		copyOfHello := *hello
		if copyOfHello.ServerName == "" && this.withoutSNI {
			copyOfHello.ServerName = this.names[0]
		}
		if copyOfHello.ServerName == "" && len(this.names) == 1 {
			if ip := net.ParseIP(strings.Trim(this.names[0], "[]")); ip != nil {
				copyOfHello.ServerName = this.names[0]
			}
		}
		names, err := (configuration.ServerNames{copyOfHello.ServerName}).Canonical()
		if err != nil || !slices.Contains(this.names, names[0]) {
			return nil, fmt.Errorf("TLS server name is not bound to this consumer")
		}
		if !this.Ready() {
			return nil, ErrNotReady
		}
		if slices.Contains(copyOfHello.SupportedProtos, acme.ALPNProto) {
			return nil, fmt.Errorf("application TLS binding does not serve challenges")
		}
		selected, err := this.manager.configForClient(&copyOfHello)
		if err != nil {
			return nil, err
		}
		selected.NextProtos = slices.Clone(this.protocols)
		return selected, nil
	}}
}

func (this *TLS) drain() error {
	// Cancellation precedes draining: blocked sources must honor their context.
	this.preparing <- struct{}{}
	<-this.preparing
	this.reloading <- struct{}{}
	<-this.reloading
	if this.ownedSource != nil {
		return this.ownedSource.Close()
	}
	return nil
}
