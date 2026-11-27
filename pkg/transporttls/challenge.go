package transporttls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// Registry routes only active proofs. It neither authorizes names nor issues
// certificates. Register completes before any listener starts.
type Registry struct {
	managers map[string]*TLS
}

func (this *Registry) Register(manager *TLS) error {
	if this.managers == nil {
		this.managers = make(map[string]*TLS)
	}
	for _, name := range manager.domains {
		if previous := this.managers[name]; previous != nil && previous != manager {
			return fmt.Errorf("multiple TLS sources claim challenge name %q", name)
		}
	}
	for _, name := range manager.domains {
		this.managers[name] = manager
	}
	return nil
}

func (this *Registry) Config(application *tls.Config) *tls.Config {
	minVersion := uint16(tls.VersionTLS12)
	if application != nil {
		minVersion = application.MinVersion
	}
	return &tls.Config{MinVersion: minVersion, SessionTicketsDisabled: true, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello == nil {
			return nil, fmt.Errorf("missing TLS ClientHello")
		}
		if slices.Contains(hello.SupportedProtos, acme.ALPNProto) {
			if len(hello.SupportedProtos) != 1 {
				return nil, fmt.Errorf("ACME ALPN must not be mixed with application protocols")
			}
			names, err := (configuration.ServerNames{hello.ServerName}).Canonical()
			if err != nil {
				return nil, fmt.Errorf("invalid challenge name")
			}
			manager := this.managers[names[0]]
			if manager == nil {
				return nil, fmt.Errorf("no registered TLS-ALPN-01 source")
			}
			return manager.configForClient(hello)
		}
		if application == nil {
			return nil, fmt.Errorf("challenge listener accepts only TLS-ALPN-01")
		}
		if application.GetConfigForClient == nil {
			return nil, fmt.Errorf("application TLS requires a consumer-specific certificate selector")
		}
		return application.GetConfigForClient(hello)
	}}
}

// Serve owns and drains challenge connections, with a bounded handshake and no
// application-data handler. Cancellation closes both listener and connections.
func (this *Registry) Serve(ctx context.Context, listener net.Listener) error {
	var mutex sync.Mutex
	connections := make(map[net.Conn]struct{})
	var wait sync.WaitGroup
	slots := make(chan struct{}, 256)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer func() {
		mutex.Lock()
		for connection := range connections {
			_ = connection.Close()
		}
		mutex.Unlock()
		wait.Wait()
	}()
	config := this.Config(nil)
	for {
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return net.ErrClosed
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = raw.Close()
			continue
		}
		mutex.Lock()
		connections[raw] = struct{}{}
		mutex.Unlock()
		wait.Add(1)
		go func() {
			defer wait.Done()
			defer func() { <-slots }()
			defer func() {
				_ = raw.Close()
				mutex.Lock()
				delete(connections, raw)
				mutex.Unlock()
			}()
			_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
			_ = tls.Server(raw, config).HandshakeContext(ctx)
		}()
	}
}
