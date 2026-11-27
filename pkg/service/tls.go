package service

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

type tlsConsumer struct {
	id, source string
	config     transporttls.Config
}

// Only enabled consumers participate. Merely defining a profile never resolves
// a path, creates an account or opens a listener.
func activeTLSConsumers(conf *configuration.Configuration) ([]tlsConsumer, error) {
	var result []tlsConsumer
	if conf.Http.IsListenerEnabled() && conf.Http.Tls.IsEnabled() {
		h := conf.Http
		profile, err := h.Tls.ServerDefinition()
		if err != nil {
			return nil, err
		}
		names, err := h.Domains.Canonical()
		if err != nil {
			return nil, err
		}
		source := "http"
		if h.Tls.Reference != "" {
			source = "tls:" + h.Tls.Reference
		}
		result = append(result, tlsConsumer{"http", source, transporttls.Config{
			Profile: profile, Names: names, StartupTimeout: h.StartupTimeout.Native(),
		}})
	}
	if conf.Monitoring.IsEnabled() && conf.Monitoring.Tls.IsEnabled() {
		m := conf.Monitoring
		profile, err := m.Tls.ServerDefinition()
		if err != nil {
			return nil, err
		}
		names, err := m.Domains.Canonical()
		if err != nil {
			return nil, err
		}
		source := "monitoring"
		if m.Tls.Reference != "" {
			source = "tls:" + m.Tls.Reference
		}
		result = append(result, tlsConsumer{"monitoring", source, transporttls.Config{
			Profile: profile, Names: names, StartupTimeout: configuration.DefaultHttpStartupTimeout.Native(),
		}})
	}
	return result, nil
}

func (this *service) prepareTLS() error {
	consumers, err := activeTLSConsumers(&this.Configuration)
	if err != nil {
		return err
	}
	this.tlsManagers = make(map[string]*transporttls.TLS)
	this.tlsBindings = make(map[string]*transporttls.Binding)
	configs := make(map[string]transporttls.Config)
	for _, consumer := range consumers {
		if previous, exists := configs[consumer.source]; exists {
			for _, name := range consumer.config.Names {
				if !slices.Contains(previous.Names, name) {
					previous.Names = append(previous.Names, name)
				}
			}
			// Sharing a source must not extend an HTTP consumer's startup budget.
			previous.StartupTimeout = min(previous.StartupTimeout, consumer.config.StartupTimeout)
			configs[consumer.source] = previous
		} else {
			configs[consumer.source] = consumer.config
		}
	}
	var names []string
	for name := range configs {
		names = append(names, name)
	}
	slices.Sort(names)
	this.tlsSourceNames = names
	stores := make(map[string]string)
	for _, name := range names {
		conf := configs[name]
		conf.ValidateKey = this.validateHTTPSKey
		conf.ValidateFiles = this.validateTLSFiles
		if conf.Profile.Acme.IsEnabled() {
			canonical, err := sys.CanonicalPath(conf.Profile.Acme.Storage)
			if err != nil {
				return fmt.Errorf("cannot resolve TLS ACME storage (details redacted)")
			}
			if previous, exists := stores[canonical]; exists {
				return fmt.Errorf("independent TLS sources %q and %q cannot share ACME storage", previous, name)
			}
			stores[canonical], conf.Profile.Acme.Storage = name, canonical
		}
		manager, err := transporttls.NewManaged(conf, nil)
		if err != nil {
			return fmt.Errorf("cannot prepare TLS source %q: %w", name, err)
		}
		this.tlsManagers[name] = manager
		if conf.Profile.Dummy {
			this.logger().With("source", name).With("names", conf.Names).
				Warn("tls.dummy=true: created an ephemeral self-signed certificate for testing only; clients do not trust it, certificate expires in 24 hours")
		}
		if conf.Profile.Acme.IsEnabled() {
			if err := this.tlsChallenges.Register(manager); err != nil {
				return err
			}
		}
	}
	for _, consumer := range consumers {
		if consumer.id == "http" && this.Configuration.Http.IsAcmeTlsAlpnOnly() {
			continue
		}
		manager := this.tlsManagers[consumer.source]
		binding, err := manager.Bind(consumer.config.Names, []string{"h2", "http/1.1"}, consumer.id == "monitoring" && len(consumer.config.Names) == 1)
		if err != nil {
			return err
		}
		this.tlsBindings[consumer.id] = binding
		if consumer.id == "monitoring" && this.monitoring != nil && this.monitoring.endpoint != nil {
			// Monitoring never dispatches public challenges on its private port.
			if err := this.monitoring.endpoint.SetTLSConfig(binding.Config()); err != nil {
				return err
			}
		}
	}
	if len(stores) != 0 {
		if !this.Configuration.Http.IsListenerEnabled() || !this.Configuration.Http.Tls.IsEnabled() {
			return fmt.Errorf("active ACME requires an enabled HTTP TLS listener")
		}
		this.tlsChallengeAddresses = slices.Clone(this.Configuration.Http.Addresses)
	}
	return nil
}

func (this *service) validateTLSFiles() error {
	candidate := cloneRuntimePathConfiguration(&this.Configuration)
	var storage string
	if configured, ok := candidate.Session.V.(*configuration.SessionFs); ok && configured != nil {
		storage = configured.Storage
	}
	return validateHTTPRuntimePaths(&candidate, storage)
}

func (this *service) prepareTLSBindings(ctx context.Context) error {
	for _, name := range this.tlsSourceNames {
		if err := this.tlsManagers[name].Prepare(ctx); err != nil {
			return fmt.Errorf("TLS source %q: %w", name, err)
		}
	}
	if this.https != nil {
		return this.https.Prepare(ctx)
	}
	return nil
}

func (this *service) closeTLS() error {
	var result error
	for _, name := range this.tlsSourceNames {
		if manager := this.tlsManagers[name]; manager != nil {
			result = errors.Join(result, manager.Close())
		}
	}
	return result
}

func (this *service) tlsRefreshFailed(source, operation string, err error) {
	if this.monitoring != nil {
		this.monitoring.tlsRenewalErrors.WithLabelValues(source).Inc()
		if this.httpTLSUses(source) {
			this.monitoring.http.renewalErrors.Inc()
		}
	}
	this.logger().With("source", source).WithError(err).
		Warn("TLS certificate " + operation + " failed; existing valid material retained")
}
