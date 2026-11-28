package service

import (
	"context"
	goerrors "errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var errStaleRuntimeGeneration = goerrors.New("runtime generation has been superseded")

// runtimeGenerations is the shared admission/ownership registry, not a second
// service or session repository. A generation owns immutable configuration;
// connections, executions and persisted sessions pin its resource lifetime.
// No repository, provider or connection callback runs while mutex is held.
type runtimeGenerations struct {
	watch configuration.WatchMode
	// Serializes commits/discard/shutdown, not ordinary admission. Slow durable
	// writes never own mutex or webPublication.
	transition  sync.Mutex
	persistence *runtimePersistence
	// Only short, in-memory browser publication uses this gate. Provider,
	// repository and connection work must stay outside both registry locks.
	webPublication     sync.RWMutex
	mutex              sync.Mutex
	initial            *runtimeGeneration
	current            *runtimeGeneration
	stopped            bool
	terminalsStopped   bool
	activeConnections  *atomic.Int64
	sessions           map[sessionConnectionKey]*runtimeSessionBinding
	revokedSessions    map[sessionConnectionKey]bool
	connections        map[managedConnection]*runtimeConnectionBinding
	maintenanceChanged func()
}

type runtimeGeneration struct {
	registry     *runtimeGenerations
	snapshot     *configuration.Snapshot
	parent       *runtimeGeneration
	flows        map[configuration.FlowName]runtimeFlowBinding
	activated    bool
	retired      bool
	references   int
	drained      chan struct{}
	httpDisabled bool
	ownership    *session.RuntimeState
}

type runtimeFlowBinding struct {
	identity    *runtimeFlowIdentity
	environment *runtimeEnvironmentRevision
	reusable    *runtimeEnvironmentRevision
	admission   *runtimeFlowRevision
	actions     *runtimeFlowRevision
}

type runtimeFlowRevision struct{ _ byte }

// Identity survives modifications, but never deletion/recreation. Its revoked
// flag is protected by the registry mutex and affects every older generation.
type runtimeFlowIdentity struct {
	revoked bool
}

// Use a non-zero-sized identity: distinct revision pointers must never compare
// equal, including when an environment is changed back to an earlier value.
type runtimeEnvironmentRevision struct{ kind reflect.Type }

type runtimeSessionBinding struct {
	generation *runtimeGeneration
	flow       runtimeFlowBinding
}

type runtimeConnectionBinding struct {
	generation *runtimeGeneration
	flow       *runtimeFlowIdentity
	session    sessionConnectionKey
}

// A short-lived selection bridges immutable provider lookup and connection
// construction without holding the registry lock or losing an activation race.
type runtimeAdmission struct {
	generation *runtimeGeneration
	active     bool
	used       bool
}

// Activation has already committed when this value is returned. Connection
// closing and session cleanup are separate, fallible post-commit operations;
// their failure must never cause the accepted snapshot to be rolled back.
type runtimeActivation struct {
	connections []managedConnection
	sessions    []sessionConnectionKey
	cleanupErr  error
}

func (this *runtimeActivation) closeConnections() error {
	return closeSessionConnections(this.connections)
}

func newRuntimeGenerations(snapshot *configuration.Snapshot, mode ...configuration.WatchMode) *runtimeGenerations {
	result := &runtimeGenerations{
		sessions:        make(map[sessionConnectionKey]*runtimeSessionBinding),
		revokedSessions: make(map[sessionConnectionKey]bool),
		connections:     make(map[managedConnection]*runtimeConnectionBinding),
	}
	if len(mode) > 0 {
		result.watch = mode[0]
	}
	initial := result.makeGeneration(snapshot, nil)
	initial.activated, initial.references = true, 1 // The active generation's lease.
	result.initial, result.current = initial, initial
	return result
}

// Only immutable parent definitions are read here. Build the candidate outside
// the admission lock; activation checks that its parent is still current.
func (this *runtimeGenerations) makeGeneration(snapshot *configuration.Snapshot, parent *runtimeGeneration) *runtimeGeneration {
	conf := snapshot.Configuration()
	result := &runtimeGeneration{
		registry: this, snapshot: snapshot, parent: parent,
		flows: make(map[configuration.FlowName]runtimeFlowBinding), drained: make(chan struct{}),
		httpDisabled: conf.Http != nil && !conf.Http.IsEnabled(),
	}
	changedEnvironments := make(map[configuration.FlowName]bool)
	changedFlows := make(map[configuration.FlowName]bool)
	orderChanged := false
	if parent != nil {
		changes := parent.snapshot.AccessChangesTo(snapshot)
		orderChanged = changes.FlowOrderChanged
		for _, change := range changes.ModifiedFlows {
			changedEnvironments[change.Name] = change.Environment
			changedFlows[change.Name] = true
		}
	}
	for _, flow := range conf.Flows {
		binding, exists := runtimeFlowBinding{}, false
		if parent != nil {
			binding, exists = parent.flows[flow.Name]
		}
		if !exists {
			binding.identity = &runtimeFlowIdentity{}
		}
		kind := reflect.TypeOf(flow.Environment.V)
		if !exists || binding.environment.kind != kind {
			binding.reusable = &runtimeEnvironmentRevision{kind: kind}
		}
		if !exists || changedEnvironments[flow.Name] {
			binding.environment = &runtimeEnvironmentRevision{kind: kind}
		}
		if !exists || this.watch == configuration.WatchModeReconnect && (changedFlows[flow.Name] || orderChanged) {
			binding.admission = &runtimeFlowRevision{}
		}
		if !exists || changedFlows[flow.Name] || this.watch == configuration.WatchModeReconnect && orderChanged {
			binding.actions = &runtimeFlowRevision{}
		}
		result.flows[flow.Name] = binding
	}
	return result
}

func (this *runtimeGenerations) prepare(snapshot *configuration.Snapshot) (*runtimeGeneration, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("runtime generation requires a configuration snapshot")
	}
	this.mutex.Lock()
	if this.stopped {
		this.mutex.Unlock()
		return nil, context.Canceled
	}
	parent := this.current
	this.mutex.Unlock()
	return this.makeGeneration(snapshot, parent), nil
}

func (this *runtimeGenerations) activate(ctx context.Context, candidate *runtimeGeneration) (activation *runtimeActivation, resultErr error) {
	activation, resultErr = this.activateState(ctx, candidate)
	if resultErr == nil && this.maintenanceChanged != nil {
		this.maintenanceChanged()
	}
	return
}

func (this *runtimeGenerations) activateState(ctx context.Context, candidate *runtimeGeneration) (*runtimeActivation, error) {
	this.transition.Lock()
	defer this.transition.Unlock()
	cleanupErr, err := this.prepareActivation(ctx, candidate)
	if err != nil {
		return nil, err
	}
	result := this.commitActivation(candidate)
	result.cleanupErr = cleanupErr
	return result, nil
}

func (this *runtimeGenerations) checkActivationLocked(ctx context.Context, candidate *runtimeGeneration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if this.stopped {
		return context.Canceled
	}
	if candidate == nil || candidate.registry != this || candidate.activated || candidate.retired {
		return fmt.Errorf("invalid runtime generation")
	}
	if candidate.parent != this.current {
		return errStaleRuntimeGeneration
	}
	return nil
}

// transition excludes shutdown/discard/other commits. Once persistence has
// published, cancellation cannot turn this infallible publication into rejection.
func (this *runtimeGenerations) commitActivation(candidate *runtimeGeneration) *runtimeActivation {
	this.webPublication.Lock()
	this.mutex.Lock()
	defer func() {
		this.mutex.Unlock()
		this.webPublication.Unlock()
	}()
	previous := this.current
	for name, flow := range previous.flows {
		if _, retained := candidate.flows[name]; !retained {
			flow.identity.revoked = true
		}
	}
	candidate.activated, candidate.references = true, 1
	candidate.parent = nil
	this.current = candidate
	previous.retired = true
	this.releaseLocked(previous)
	result := &runtimeActivation{}
	for conn, binding := range this.connections {
		if binding.flow != nil && (binding.flow.revoked || !this.flowAllowedLocked(binding.generation, binding.session.flow)) {
			result.connections = append(result.connections, conn)
		}
	}
	for key, binding := range this.sessions {
		if binding.flow.identity.revoked {
			result.sessions = append(result.sessions, key)
		}
	}
	return result
}

func (this *runtimeGenerations) discard(candidate *runtimeGeneration) bool {
	this.transition.Lock()
	defer this.transition.Unlock()
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if candidate == nil || candidate.registry != this || candidate.activated {
		return false
	}
	if candidate.retired {
		return true
	}
	candidate.retired = true
	candidate.parent = nil
	close(candidate.drained)
	return true
}

func (this *runtimeGenerations) allConnections() []managedConnection {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	result := make([]managedConnection, 0, len(this.connections))
	for conn := range this.connections {
		result = append(result, conn)
	}
	return result
}

// retain also permits background cleanup/executions belonging to a retired but
// still pinned generation. It is not permission to admit a new connection.
func (this *runtimeGenerations) retain(generation *runtimeGeneration) (func(), error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if !this.liveLocked(generation) {
		return nil, context.Canceled
	}
	generation.references++
	return this.releaseFunc(generation), nil
}

func (this *runtimeGenerations) liveLocked(generation *runtimeGeneration) bool {
	return generation != nil && generation.registry == this && generation.activated && generation.references > 0
}

func (this *runtimeGenerations) releaseFunc(generation *runtimeGeneration) func() {
	return sync.OnceFunc(func() {
		this.mutex.Lock()
		defer this.mutex.Unlock()
		this.releaseLocked(generation)
	})
}

func (*runtimeGenerations) releaseLocked(generation *runtimeGeneration) {
	generation.references--
	if generation.references == 0 && generation.retired {
		close(generation.drained)
	}
}

func (this *runtimeGenerations) allowFlow(generation *runtimeGeneration, name configuration.FlowName) bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.stopped || !this.liveLocked(generation) {
		return false
	}
	return this.flowAllowedLocked(generation, name)
}

func (this *runtimeGenerations) flowAllowedLocked(generation *runtimeGeneration, name configuration.FlowName) bool {
	flow, exists := generation.flows[name]
	if !exists || flow.identity.revoked {
		return false
	}
	return this.watch != configuration.WatchModeReconnect || flow.admission == this.current.flows[name].admission
}

func (this *runtimeGenerations) environmentsCompatible(left, right runtimeFlowBinding) bool {
	return left.environment == right.environment ||
		this.watch == configuration.WatchModeReuse && left.reusable == right.reusable
}

// admit pins the admission's generation before authentication. A later ordinary
// modification does not change its rules; deletion is checked again on binding.
func (this *runtimeGenerations) admit(generation *runtimeGeneration, conn managedConnection) (func(), error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if generation != this.current {
		return nil, context.Canceled
	}
	return this.admitLocked(generation, conn)
}

// Selection is the admission boundary, before any provider callback. A later
// ordinary modification cannot reinterpret an already selected SSH connection.
func (this *runtimeGenerations) selectCurrent() (*runtimeAdmission, func(), error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.stopped {
		return nil, nil, context.Canceled
	}
	generation := this.current
	generation.references++
	selection := &runtimeAdmission{generation: generation, active: true}
	return selection, sync.OnceFunc(func() {
		this.mutex.Lock()
		defer this.mutex.Unlock()
		selection.active = false
		this.releaseLocked(generation)
	}), nil
}

func (this *runtimeGenerations) admitSelected(selection *runtimeAdmission, conn managedConnection) (func(), error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if selection == nil || selection.generation.registry != this || !selection.active || selection.used {
		return nil, context.Canceled
	}
	selection.used = true
	return this.admitLocked(selection.generation, conn)
}

func (this *runtimeGenerations) admitLocked(generation *runtimeGeneration, conn managedConnection) (func(), error) {
	if isNilDependency(conn) || !reflect.TypeOf(conn).Comparable() {
		return nil, fmt.Errorf("runtime admission requires an identifiable connection")
	}
	if this.stopped || !this.liveLocked(generation) {
		return nil, context.Canceled
	}
	if _, terminal := conn.(*terminalConnection); terminal && this.terminalsStopped {
		return nil, context.Canceled
	}
	if _, exists := this.connections[conn]; exists {
		return nil, fmt.Errorf("connection already has a runtime admission")
	}
	binding := &runtimeConnectionBinding{generation: generation}
	this.connections[conn] = binding
	generation.references++
	return sync.OnceFunc(func() {
		this.mutex.Lock()
		defer this.mutex.Unlock()
		if this.connections[conn] == binding {
			delete(this.connections, conn)
		}
		this.releaseLocked(generation)
	}), nil
}

func (this *runtimeGenerations) untrack(conn managedConnection) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	// Closing a socket does not release the handler's resource lease. Its
	// admission release runs only after the owning handler has finished.
	delete(this.connections, conn)
}

func (this *runtimeGenerations) bindConnection(conn managedConnection, sess session.Session) bool {
	if sess == nil {
		return false
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	binding := this.connections[conn]
	if this.stopped || binding == nil {
		return false
	}
	flow, exists := binding.generation.flows[key.flow]
	if !exists || flow.identity.revoked || binding.flow != nil && binding.flow != flow.identity {
		return false
	}
	if err := this.bindSessionLocked(binding.generation, key, false); err != nil {
		return false
	}
	binding.flow = flow.identity
	binding.session = key
	return true
}

func (this *runtimeGenerations) bindSession(generation *runtimeGeneration, sess session.Session, created bool) error {
	if sess == nil {
		return errors.Permission.Newf("runtime ownership requires a session")
	}
	if this.persistence != nil && created {
		provider, ok := sess.(session.RuntimeOwnershipSession)
		if !ok || generation.ownership == nil {
			return errors.Permission.Newf("new session has no persistent runtime owner")
		}
		owner, err := provider.RuntimeOwnership(context.Background())
		if err != nil || owner == nil || !owner.Matches(generation.ownership.Flows[sess.Flow()]) {
			return errors.Permission.Newf("new session has no matching persistent runtime owner")
		}
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.mutex.Lock()
	err := this.bindSessionLocked(generation, key, created)
	this.mutex.Unlock()
	if err != nil && created && this.maintenanceChanged != nil {
		this.maintenanceChanged()
	}
	return err
}

func (this *runtimeGenerations) bindSessionLocked(generation *runtimeGeneration, key sessionConnectionKey, created bool) error {
	if !this.liveLocked(generation) {
		return context.Canceled
	}
	flow, exists := generation.flows[key.flow]
	if !exists {
		return errors.Permission.Newf("session flow is not part of the admitted configuration")
	}
	binding := this.sessions[key]
	if binding == nil {
		if this.persistence != nil && !created {
			return errors.Permission.Newf("session has no registered persistent runtime owner")
		}
		owner, ownerFlow := generation, flow
		if !created {
			// Unknown persisted sessions belong to startup, never implicitly
			// to the newest definition after a reload.
			var known bool
			ownerFlow, known = this.initial.flows[key.flow]
			owner = this.initial
			if !known || !this.liveLocked(owner) {
				return errors.Permission.Newf("session has no known runtime owner")
			}
		}
		owner.references++
		binding = &runtimeSessionBinding{generation: owner, flow: ownerFlow}
		this.sessions[key] = binding
	}
	// A session created concurrently with deletion remains owned for cleanup,
	// even though it must never become a successful authentication result.
	if this.stopped || !this.flowAllowedLocked(generation, key.flow) || binding.flow.identity.revoked || this.revokedSessions[key] {
		return errors.Permission.Newf("session flow has been removed")
	}
	if flow.identity != binding.flow.identity || !this.environmentsCompatible(flow, binding.flow) {
		return errors.Permission.Newf("session belongs to a different environment revision")
	}
	return nil
}

func (this *runtimeGenerations) sessionCompatible(generation *runtimeGeneration, sess session.Session) bool {
	if sess == nil {
		return false
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.stopped || !this.liveLocked(generation) {
		return false
	}
	flow, exists := generation.flows[key.flow]
	if !exists || flow.identity.revoked {
		return false
	}
	binding := this.sessions[key]
	if this.revokedSessions[key] {
		return false
	}
	if binding != nil {
		return !binding.flow.identity.revoked && binding.flow.identity == flow.identity && this.environmentsCompatible(flow, binding.flow)
	}
	if this.persistence != nil {
		return false
	}
	initial, exists := this.initial.flows[key.flow]
	return exists && this.liveLocked(this.initial) && !initial.identity.revoked && initial.identity == flow.identity && this.environmentsCompatible(initial, flow)
}

func (this *runtimeGenerations) sessionRevoked(sess session.Session) bool {
	if sess == nil {
		return false
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.revokedSessions[key] {
		return true
	}
	if binding := this.sessions[key]; binding != nil {
		return binding.flow.identity.revoked
	}
	if this.persistence != nil {
		return true
	}
	flow, exists := this.initial.flows[key.flow]
	return !exists || flow.identity.revoked
}

func (this *runtimeGenerations) sessionOwner(sess session.Session) *runtimeGeneration {
	if sess == nil {
		return nil
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if binding := this.sessions[key]; binding != nil {
		return binding.generation
	}
	return nil
}

// Retain atomically with ownership lookup: deletion may release the session's
// own lease immediately afterwards, but not the caller's provider/audit work.
func (this *runtimeGenerations) retainSessionOwner(key sessionConnectionKey) (*runtimeGeneration, func(), error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.stopped {
		return nil, nil, context.Canceled
	}
	binding := this.sessions[key]
	if binding == nil || !this.liveLocked(binding.generation) {
		return nil, nil, session.ErrNoSuchSession
	}
	binding.generation.references++
	return binding.generation, this.releaseFunc(binding.generation), nil
}

func (this *runtimeGenerations) sessionKeyRevoked(key sessionConnectionKey) bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	binding := this.sessions[key]
	return this.revokedSessions[key] || binding == nil || binding.flow.identity.revoked
}

func (this *runtimeGenerations) hasSession(key sessionConnectionKey) bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.sessions[key] != nil
}

func (this *runtimeGenerations) sessionFlowRemoved(key sessionConnectionKey) bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	binding := this.sessions[key]
	return binding != nil && binding.flow.identity.revoked
}

func (this *runtimeGenerations) reloaded() bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.current != this.initial
}

func (this *runtimeGenerations) knownFlow(name configuration.FlowName) bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if _, exists := this.current.flows[name]; exists {
		return true
	}
	for key := range this.sessions {
		if key.flow == name {
			return true
		}
	}
	return false
}

// Call only after durable deletion, not after merely disposing an environment.
func (this *runtimeGenerations) finalSessionDeleted(flow configuration.FlowName, id session.Id) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	key := sessionConnectionKey{flow: flow, id: id}
	delete(this.revokedSessions, key)
	if binding := this.sessions[key]; binding != nil {
		delete(this.sessions, key)
		this.releaseLocked(binding.generation)
	}
}

func (this *runtimeGenerations) stop() {
	this.transition.Lock()
	defer this.transition.Unlock()
	this.stopState()
}

func (this *runtimeGenerations) stopState() {
	this.webPublication.Lock()
	defer this.webPublication.Unlock()
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if !this.stopped {
		this.stopped = true
		this.current.retired = true
		this.releaseLocked(this.current)
	}
}

// Shutdown releases in-memory session ownership after background workers stop.
// It does not delete or dispose any persisted session or external resource.
func (this *runtimeGenerations) forgetSessions() {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	for key, binding := range this.sessions {
		delete(this.sessions, key)
		this.releaseLocked(binding.generation)
	}
	clear(this.revokedSessions)
}

// Individual management/OIDC revocations share the same gate across every
// generation. The session tombstone survives until durable deletion.
func (this *runtimeGenerations) revokeSession(flow configuration.FlowName, id session.Id) []managedConnection {
	this.mutex.Lock()
	key := sessionConnectionKey{flow: flow, id: id}
	changed := !this.revokedSessions[key]
	this.revokedSessions[key] = true
	result := this.sessionConnectionsLocked(key)
	this.mutex.Unlock()
	if changed && this.maintenanceChanged != nil {
		this.maintenanceChanged()
	}
	return result
}

func (this *runtimeGenerations) snapshotSessionConnections(flow configuration.FlowName, id session.Id) []managedConnection {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.sessionConnectionsLocked(sessionConnectionKey{flow: flow, id: id})
}

func (this *runtimeGenerations) sessionConnectionsLocked(key sessionConnectionKey) []managedConnection {
	var result []managedConnection
	for conn, binding := range this.connections {
		if binding.flow != nil && binding.session == key {
			result = append(result, conn)
		}
	}
	return result
}

func (this *runtimeGenerations) closeTerminals() []managedConnection {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.terminalsStopped = true
	var result []managedConnection
	for conn := range this.connections {
		if _, terminal := conn.(*terminalConnection); terminal {
			result = append(result, conn)
		}
	}
	return result
}

func (this *service) connectionCounter() *atomic.Int64 {
	if this.runtime != nil && this.runtime.activeConnections != nil {
		return this.runtime.activeConnections
	}
	return &this.activeConnections
}
