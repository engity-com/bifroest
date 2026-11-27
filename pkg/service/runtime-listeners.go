package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

type listenerHandlerContextKey struct{}

// Duplicate SSH :0 entries are distinct inputs. Preserve their ordinal while
// matching unchanged addresses independently of declaration order.
type runtimeListenerKey struct {
	transport string
	address   string
	ordinal   int
}

type runtimeListenerSpec struct {
	key     runtimeListenerKey
	address bnet.Address
}

type runtimeListeners struct {
	owner  *service
	ctx    context.Context
	cancel context.CancelCauseFunc
	bind   func(bnet.Address) (net.Listener, error)
	done   chan struct{}
	wake   chan struct{}

	// The topology commit and new SSH admissions are linearized together.
	// No provider/repository calls or listener Close/Accept run under mutex.
	admissions   sync.RWMutex
	transitions  sync.Mutex
	mutex        sync.Mutex
	scopes       map[runtimeListenerKey]*runtimeListener
	version      uint64
	ready        bool
	prepared     bool
	stopped      bool
	failure      error
	closeErr     error
	forced       bool
	workers      sync.WaitGroup
	closing      sync.Mutex
	pendingClose []net.Listener
}

// This stable net.Listener owns one original Serve scope and its protection
// budgets, not its accepted connections. Detaching the physical listener does
// not end Serve while a transport or SSH handler still needs that scope.
type runtimeListener struct {
	manager    *runtimeListeners
	spec       runtimeListenerSpec
	physical   net.Listener
	address    net.Addr
	changed    chan struct{}
	transports int
	handlers   int
	started    bool
	retired    bool
	expected   bool
}

type runtimeListenerPlan struct {
	manager *runtimeListeners
	version uint64
	specs   []runtimeListenerSpec
	added   map[runtimeListenerKey]net.Listener
}

func newRuntimeListeners(svc *service, parent context.Context, bind func(bnet.Address) (net.Listener, error)) *runtimeListeners {
	if bind == nil {
		bind = func(address bnet.Address) (net.Listener, error) { return address.Listen() }
	}
	ctx, cancel := context.WithCancelCause(parent)
	return &runtimeListeners{owner: svc, ctx: ctx, cancel: cancel, bind: bind, done: make(chan struct{}), wake: make(chan struct{}, 1), scopes: make(map[runtimeListenerKey]*runtimeListener), prepared: svc.https == nil && len(svc.tlsManagers) == 0}
}

func runtimeListenerSpecs(conf configuration.Configuration, hasHTTPS bool, hasChallenges ...bool) []runtimeListenerSpec {
	var result []runtimeListenerSpec
	groups := []struct {
		transport string
		addresses bnet.NetAddresses
	}{}
	if conf.Ssh.IsEnabled() {
		groups = append(groups, struct {
			transport string
			addresses bnet.NetAddresses
		}{"SSH", conf.Ssh.Addresses})
	}
	if conf.Http.IsEnabled() && hasHTTPS {
		groups = append(groups, struct {
			transport string
			addresses bnet.NetAddresses
		}{"HTTPS", conf.Http.Addresses})
	}
	if conf.Http.IsAcmeTlsAlpnOnly() && len(hasChallenges) > 0 && hasChallenges[0] {
		groups = append(groups, struct {
			transport string
			addresses bnet.NetAddresses
		}{"TLS challenge", conf.Http.Addresses})
	}
	for _, group := range groups {
		counts := make(map[string]int)
		for _, address := range group.addresses {
			name := address.String()
			result = append(result, runtimeListenerSpec{key: runtimeListenerKey{group.transport, name, counts[name]}, address: address})
			counts[name]++
		}
	}
	return result
}

func (this *runtimeListeners) prepare(ctx context.Context, conf configuration.Configuration) (plan *runtimeListenerPlan, resultErr error) {
	// A previous committed detach may have failed to release its port. Retry
	// before binding, or re-enabling that same fixed address could never commit
	// the next activation which would otherwise trigger cleanup.
	if err := this.closeDetached(); err != nil {
		this.owner.logger().Warn("cannot close previously detached listeners; cleanup remains pending")
	}
	this.mutex.Lock()
	if this.stopped || this.ctx.Err() != nil {
		this.mutex.Unlock()
		return nil, context.Canceled
	}
	plan = &runtimeListenerPlan{manager: this, version: this.version, specs: runtimeListenerSpecs(conf, this.owner.https != nil, len(this.owner.tlsChallengeAddresses) > 0), added: make(map[runtimeListenerKey]net.Listener)}
	var missing []runtimeListenerSpec
	for _, spec := range plan.specs {
		if scope := this.scopes[spec.key]; scope == nil || scope.physical == nil || scope.retired {
			missing = append(missing, spec)
		}
	}
	this.mutex.Unlock()
	success := false
	defer func() {
		if !success {
			resultErr = errors.Join(resultErr, plan.close())
			plan = nil
		}
	}()
	for _, spec := range missing {
		if ctx.Err() != nil || this.ctx.Err() != nil {
			return plan, context.Canceled
		}
		listener, err := this.bind(spec.address)
		if isNilDependency(listener) {
			listener = nil
		}
		if listener != nil {
			plan.added[spec.key] = listener
		}
		if err != nil {
			return plan, fmt.Errorf("cannot bind %s listener %v: %w", spec.key.transport, spec.address, err)
		}
		if listener == nil {
			return plan, fmt.Errorf("cannot bind %s listener %v: no listener returned", spec.key.transport, spec.address)
		}
	}
	if ctx.Err() != nil || this.ctx.Err() != nil {
		return plan, context.Canceled
	}
	success = true
	return plan, nil
}

func (this *runtimeListenerPlan) close() (result error) {
	for key, listener := range this.added {
		if err := listener.Close(); this.manager.owner.isProblematicError(err) {
			result = errors.Join(result, fmt.Errorf("cannot close prepared %s listener: %w", key.transport, err))
			this.manager.mutex.Lock()
			this.manager.pendingClose = append(this.manager.pendingClose, listener)
			this.manager.mutex.Unlock()
		}
		delete(this.added, key)
	}
	return result
}

// Caller holds admissions exclusively and mutex. All fallible work precedes
// this operation; sockets detached here are closed only after publishing.
func (this *runtimeListeners) installLocked(plan *runtimeListenerPlan) []net.Listener {
	wanted := make(map[runtimeListenerKey]bool, len(plan.specs))
	for _, spec := range plan.specs {
		wanted[spec.key] = true
	}
	var detached []net.Listener
	for key, scope := range this.scopes {
		if !wanted[key] && scope.physical != nil {
			detached = append(detached, scope.physical)
			scope.physical = nil
			scope.notifyLocked()
			scope.retireIfIdleLocked()
		}
	}
	for _, spec := range plan.specs {
		listener := plan.added[spec.key]
		if listener == nil {
			continue
		}
		scope := this.scopes[spec.key]
		if scope == nil || scope.retired {
			scope = &runtimeListener{manager: this, spec: spec, changed: make(chan struct{})}
			this.scopes[spec.key] = scope
		}
		scope.physical, scope.address = listener, listener.Addr()
		scope.notifyLocked()
		delete(plan.added, spec.key)
	}
	this.version++
	return detached
}

func (this *runtimeListener) notifyLocked() {
	close(this.changed)
	this.changed = make(chan struct{})
}

func (this *runtimeListener) retireIfIdleLocked() {
	if !this.retired && this.physical == nil && this.transports == 0 && this.handlers == 0 {
		this.retired = true
		this.expected = true
		this.notifyLocked()
		if this.manager.scopes[this.spec.key] == this {
			delete(this.manager.scopes, this.spec.key)
		}
	}
}

func (this *runtimeListener) Accept() (net.Conn, error) {
	manager := this.manager
	for {
		manager.mutex.Lock()
		if manager.stopped || this.retired {
			manager.mutex.Unlock()
			return nil, net.ErrClosed
		}
		physical, changed := this.physical, this.changed
		manager.mutex.Unlock()
		if physical == nil {
			select {
			case <-changed:
			case <-manager.ctx.Done():
				return nil, net.ErrClosed
			}
			continue
		}
		conn, err := physical.Accept()
		manager.admissions.RLock()
		manager.mutex.Lock()
		stale := manager.stopped || this.retired || this.physical != physical
		if !stale && err == nil {
			this.transports++
		}
		manager.mutex.Unlock()
		manager.admissions.RUnlock()
		if stale {
			if conn != nil {
				_ = conn.Close()
			}
			continue
		}
		if err != nil {
			return nil, err // Unexpected input failure remains process-critical.
		}
		return &runtimeListenerConn{Conn: conn, scope: this}, nil
	}
}

func (this *runtimeListener) Addr() net.Addr {
	this.manager.mutex.Lock()
	defer this.manager.mutex.Unlock()
	return this.address
}

func (this *runtimeListener) Close() error {
	this.manager.transitions.Lock()
	this.manager.mutex.Lock()
	physical := this.physical
	this.physical = nil
	this.retired = true
	if physical != nil {
		// Invalidate plans which intended to retain this input, even if the
		// server's completion callback has not reported its failure yet.
		this.manager.version++
	}
	this.notifyLocked()
	this.manager.mutex.Unlock()
	this.manager.transitions.Unlock()
	if physical != nil {
		err := physical.Close()
		if this.manager.owner.isProblematicError(err) {
			this.manager.mutex.Lock()
			this.manager.pendingClose = append(this.manager.pendingClose, physical)
			this.manager.mutex.Unlock()
		}
		return err
	}
	return nil
}

type runtimeListenerConn struct {
	net.Conn
	scope *runtimeListener
	once  sync.Once
	err   error
}

func (this *runtimeListenerConn) Close() error {
	this.once.Do(func() {
		this.err = this.Conn.Close()
		scope := this.scope
		scope.manager.mutex.Lock()
		scope.transports--
		scope.retireIfIdleLocked()
		scope.manager.mutex.Unlock()
	})
	return this.err
}

func (this *runtimeListener) admitSSH(ctx essh.Context, conn net.Conn) (net.Conn, error) {
	manager := this.manager
	manager.admissions.RLock()
	manager.mutex.Lock()
	if manager.stopped || this.retired || this.physical == nil {
		manager.mutex.Unlock()
		manager.admissions.RUnlock()
		return nil, nil
	}
	this.handlers++
	manager.mutex.Unlock()
	release := sync.OnceFunc(func() {
		manager.mutex.Lock()
		this.handlers--
		this.retireIfIdleLocked()
		manager.mutex.Unlock()
	})
	selection, releaseSelection, err := manager.owner.runtime.selectCurrent()
	manager.admissions.RUnlock()
	if err != nil {
		release()
		return nil, err
	}
	defer releaseSelection()
	ctx.SetValue(listenerHandlerContextKey{}, release)
	wrapped, err := manager.owner.admitSelectedSshConnection(ctx, conn, selection)
	if err != nil || wrapped == nil {
		release()
	}
	return wrapped, err
}

func (this *runtimeListeners) startScopes(transport string) {
	this.mutex.Lock()
	if this.stopped || this.ctx.Err() != nil {
		this.mutex.Unlock()
		return
	}
	var scopes []*runtimeListener
	for _, scope := range this.scopes {
		if !scope.started && !scope.retired && scope.physical != nil && scope.spec.key.transport == transport {
			scope.started = true
			scopes = append(scopes, scope)
			this.workers.Add(1)
		}
	}
	this.mutex.Unlock()
	for _, scope := range scopes {
		go func() {
			defer this.workers.Done()
			input := boundInput{scope, scope.spec.address, transport}
			this.owner.logger().With("address", scope.Addr()).With("transport", transport).Info("listening...")
			var err error
			switch transport {
			case "HTTPS":
				err = this.owner.https.Serve(scope)
			case "TLS challenge":
				err = this.owner.tlsChallenges.Serve(this.ctx, scope)
			default:
				// Construct once per listener, never copy or mutate a used server.
				server := &essh.Server{}
				this.owner.configureServer(this.owner, server, this.owner.resources.hostKeys)
				if this.owner.Configuration.Ssh.ProxyProtocol {
					server.ProxyProtocol = new(essh.ProxyProtocolConfig)
				}
				server.ConnCallback = scope.admitSSH
				err = server.Serve(this.ctx, scope)
			}
			this.completed(inputResult{input, "listener", err}, scope)
		}()
	}
}

func (this *runtimeListeners) start(input boundInput, operation string, serve func() error) {
	this.workers.Add(1) // Startup only, before ready is published.
	go func() {
		defer this.workers.Done()
		this.completed(inputResult{input, operation, serve()}, nil)
	}()
}

func (this *runtimeListeners) completed(result inputResult, scope *runtimeListener) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.forced = this.forced || errors.Is(result.err, essh.ErrGracefulShutdownTimeout)
	if scope != nil && scope.expected && !this.stopped {
		return // A detached, fully drained scope is not a listener failure.
	}
	if this.stopped || this.ctx.Err() != nil {
		if this.owner.isProblematicError(result.err) && !errors.Is(result.err, http.ErrServerClosed) && !errors.Is(result.err, https.ErrClosed) {
			this.closeErr = errors.Join(this.closeErr, inputFailure(result))
		}
	} else if result.operation == "HTTPS preparation" && result.err == nil {
		this.prepared = true
	} else if this.failure == nil {
		this.failure = inputFailure(result)
	}
	select {
	case this.wake <- struct{}{}:
	default:
	}
}

// Only pre-commit errors are returned as errors. Once accepted, fallible socket
// closing/revocation is reported separately and must not roll back the snapshot.
func (this *service) activateGeneration(ctx context.Context, candidate *service) (*runtimeActivation, error) {
	if this.resources == nil || candidate == nil || candidate.resources != this.resources {
		return nil, fmt.Errorf("runtime activation requires prepared shared resources")
	}
	lifetime, _, finish, err := this.resources.beginPreparation(ctx)
	if err != nil {
		return nil, err
	}
	defer finish(false)
	this.resources.mutex.Lock()
	inputs := this.resources.listeners
	this.resources.mutex.Unlock()
	if inputs == nil {
		return nil, fmt.Errorf("runtime listeners are not running")
	}
	plan, err := inputs.prepare(lifetime, candidate.Configuration)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := plan.close(); err != nil {
			this.logger().Warn("cannot close unused prepared listeners")
		}
	}()
	inputs.transitions.Lock()
	this.runtime.transition.Lock()
	inputs.mutex.Lock()
	if !inputs.ready || inputs.stopped || inputs.failure != nil || inputs.ctx.Err() != nil || plan.version != inputs.version {
		inputs.mutex.Unlock()
		this.runtime.transition.Unlock()
		inputs.transitions.Unlock()
		return nil, fmt.Errorf("runtime listener preparation is stale or stopping")
	}
	inputs.mutex.Unlock()
	cleanupErr, err := this.runtime.prepareActivation(lifetime, candidate.generation)
	if err != nil {
		this.runtime.transition.Unlock()
		inputs.transitions.Unlock()
		return nil, err
	}
	inputs.admissions.Lock()
	inputs.mutex.Lock()
	activation := this.runtime.commitActivation(candidate.generation)
	activation.cleanupErr = cleanupErr
	detached := inputs.installLocked(plan)
	if candidate.monitoring != nil {
		candidate.monitoring.service.Store(candidate)
		candidate.monitoring.setReady(len(plan.specs) > 0)
	}
	inputs.pendingClose = append(inputs.pendingClose, detached...)
	inputs.mutex.Unlock()
	inputs.admissions.Unlock()
	this.runtime.transition.Unlock()
	inputs.transitions.Unlock()
	if candidate.monitoring != nil {
		for _, labels := range candidate.monitoring.flows {
			_ = candidate.monitoring.tasks.WithLabelValues(labels...)
		}
	}
	if this.runtime.maintenanceChanged != nil {
		this.runtime.maintenanceChanged()
	}
	activation.cleanupErr = errors.Join(activation.cleanupErr, inputs.closeDetached())
	inputs.startScopes("HTTPS")
	inputs.startScopes("TLS challenge")
	inputs.startScopes("SSH")
	activation.cleanupErr = errors.Join(activation.cleanupErr, activation.closeConnections())
	if activation.cleanupErr != nil {
		this.logger().Warn("configuration activated; cleanup requires operator attention")
	}
	return activation, nil
}

func (this *runtimeListeners) stop() (result error) {
	this.transitions.Lock()
	this.admissions.Lock()
	this.mutex.Lock()
	this.stopped, this.ready = true, false
	var physical []net.Listener
	for _, scope := range this.scopes {
		if scope.physical != nil {
			physical = append(physical, scope.physical)
			scope.physical = nil
		}
		scope.notifyLocked()
	}
	this.pendingClose = append(this.pendingClose, physical...)
	this.mutex.Unlock()
	this.admissions.Unlock()
	this.transitions.Unlock()
	return this.closeDetached()
}

func (this *runtimeListeners) closeDetached() (result error) {
	this.closing.Lock()
	defer this.closing.Unlock()
	this.mutex.Lock()
	pending := this.pendingClose
	this.pendingClose = nil
	this.mutex.Unlock()
	var failed []net.Listener
	for _, listener := range pending {
		if err := listener.Close(); this.owner.isProblematicError(err) {
			result = errors.Join(result, err)
			failed = append(failed, listener)
		}
	}
	this.mutex.Lock()
	this.pendingClose = append(this.pendingClose, failed...)
	this.mutex.Unlock()
	return result
}
