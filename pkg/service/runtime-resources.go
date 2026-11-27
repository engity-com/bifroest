package service

import (
	"context"
	stdcrypto "crypto"
	goerrors "errors"
	"fmt"
	"sync"

	clibase "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
)

// The initial service owns process resources; subsequent services are immutable
// generation views borrowing them. No candidate opens the session store, audit
// journals, Recording writers, IMP master or listeners a second time.
type runtimeResources struct {
	owner        *service
	hostKeys     []crypto.PrivateKey
	environments *environment.FacadeFactory
	preparations *connectionLifecycle
	handlers     *connectionLifecycle
	ctx          context.Context
	cancel       context.CancelFunc

	mutex      sync.Mutex
	views      map[*service]struct{}
	listeners  *runtimeListeners
	cleanup    sync.WaitGroup
	cleanupErr error
	closeOnce  sync.Once
	closeErr   error

	keysMutex    sync.Mutex
	sshKeys      map[*service][]crypto.PublicKey
	tlsKeys      []crypto.PublicKey
	actionsMutex sync.Mutex
	actions      map[sessionConnectionKey]*runtimeSessionAction
	oidcLocks    authorization.OidcSessionLocks
}

func newRuntimeResources(owner *service) *runtimeResources {
	ctx, cancel := context.WithCancel(context.Background())
	result := &runtimeResources{
		owner: owner, preparations: newConnectionLifecycle(), handlers: newConnectionLifecycle(), ctx: ctx, cancel: cancel,
		views: make(map[*service]struct{}), sshKeys: make(map[*service][]crypto.PublicKey),
		actions: make(map[sessionConnectionKey]*runtimeSessionAction),
	}
	owner.runtime.maintenanceChanged = result.maintenanceChanged
	return result
}

func (this *runtimeResources) track(svc *service) {
	this.mutex.Lock()
	this.views[svc] = struct{}{}
	this.cleanup.Add(1)
	this.mutex.Unlock()
	go func() {
		defer this.cleanup.Done()
		<-svc.generation.drained
		err := svc.closeGeneration()
		this.keysMutex.Lock()
		delete(this.sshKeys, svc)
		this.keysMutex.Unlock()
		this.mutex.Lock()
		delete(this.views, svc)
		this.cleanupErr = goerrors.Join(this.cleanupErr, err)
		this.mutex.Unlock()
		close(svc.generationClosed)
	}()
}

// Preparation gets a generation lifetime context, not a request context that
// would cancel successfully prepared SSH repositories when the reload returns.
// Cancellation of the request or shutdown is linked only while preparing.
func (this *runtimeResources) beginPreparation(ctx context.Context) (context.Context, context.CancelFunc, func(bool), error) {
	release, ok := this.preparations.register()
	if !ok {
		return nil, nil, nil, context.Canceled
	}
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	requestDone, shutdownDone := make(chan struct{}), make(chan struct{})
	stopRequest := context.AfterFunc(ctx, func() { cancel(); close(requestDone) })
	stopShutdown := context.AfterFunc(this.ctx, func() { cancel(); close(shutdownDone) })
	var finished sync.Once
	finish := func(success bool) {
		finished.Do(func() {
			// A triggered AfterFunc may still be running when stop returns false.
			// Join it before deciding that the lifetime context can be published.
			if !stopRequest() {
				<-requestDone
			}
			if !stopShutdown() {
				<-shutdownDone
			}
			if !success {
				cancel()
			}
			release()
		})
	}
	if ctx.Err() != nil || this.ctx.Err() != nil {
		finish(false)
		return nil, nil, nil, context.Canceled
	}
	return lifetime, cancel, finish, nil
}

// prepareGeneration deliberately does not activate or start workers/listeners.
// The later dispatcher must commit a fully prepared candidate as one operation.
func (this *service) prepareGeneration(ctx context.Context, conf configuration.Configuration) (candidate *service, resultErr error) {
	ctx = common.WithProviderBootstrapDisabled(ctx)
	shared := this.resources
	if shared == nil || shared.environments == nil {
		return nil, fmt.Errorf("runtime resources are not prepared")
	}
	lifetime, cancel, finish, err := shared.beginPreparation(ctx)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		finish(success)
		if success && lifetime.Err() != nil {
			// Cancellation can arrive between the last check and unlinking
			// the preparation context. Never return a broken candidate.
			candidate.runtime.discard(candidate.generation)
			<-candidate.generationClosed
			resultErr = goerrors.Join(lifetime.Err(), candidate.generationCloseErr)
			candidate = nil
		}
	}()
	snapshot, err := configuration.NewSnapshot(conf)
	if err != nil {
		return nil, err
	}
	conf = snapshot.Configuration()
	if err := validateRuntimePaths(&conf); err != nil {
		return nil, err
	}
	snapshot, err = configuration.NewSnapshot(conf)
	if err != nil {
		return nil, err
	}
	// These settings own shared resources/transport state. Until a dedicated
	// reconfiguration path exists, reject the entire candidate, never ignore it.
	sections := shared.restartSections(snapshot)
	if len(sections) > 0 {
		return nil, &runtimeRestartRequiredError{sections: sections}
	}
	generation, err := this.runtime.prepare(snapshot)
	if err != nil {
		return nil, err
	}
	owner := *shared.owner.Service
	owner.Configuration = snapshot.Configuration()
	candidate = &service{
		Service: &owner, runtime: this.runtime, generation: generation, resources: shared,
		monitoring: this.monitoring.view(owner.Configuration), generationClosed: make(chan struct{}),
		connectionLifecycle: newConnectionLifecycle(), executions: newConnectionLifecycle(),
		terminalAdmissions: newConnectionLifecycle(),
	}
	candidate.terminalContext, candidate.cancelTerminals = context.WithCancel(context.Background())
	// providerCancel belongs to this view even after successful preparation.
	candidate.providerCancel = cancel
	defer func(prepared *service) {
		if !success {
			prepared.runtime.discard(prepared.generation)
			resultErr = goerrors.Join(resultErr, prepared.closeGeneration())
			shared.keysMutex.Lock()
			delete(shared.sshKeys, prepared)
			shared.keysMutex.Unlock()
		}
	}(candidate)
	if err := candidate.borrowResources(shared.owner); err != nil {
		return nil, err
	}
	if err := shared.reserveSSHKeys(lifetime, candidate); err != nil {
		return nil, err
	}
	if err := candidate.prepareGenerationProviders(lifetime); err != nil {
		return nil, err
	}
	if err := candidate.prepareRuntimeOwnership(generation.parent.ownership); err != nil {
		return nil, err
	}
	candidate.refineRuntimeAccessRevisions()
	if err := candidate.prepareServer(lifetime, candidate, shared.hostKeys); err != nil {
		return nil, err
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	shared.track(candidate)
	success = true
	return candidate, nil
}

func (this *service) borrowResources(owner *service) error {
	this.sessions, this.alternatives, this.imp = owner.sessions, owner.alternatives, owner.imp
	this.https = owner.https
	this.tlsManagers, this.tlsBindings, this.tlsSourceNames = owner.tlsManagers, owner.tlsBindings, owner.tlsSourceNames
	this.sessionConnections.runtime = this.runtime
	this.sessionConnections.observeAges = owner.sessionConnections.observeAges
	this.auditIdentities, this.auditRecorders = owner.auditIdentities, owner.auditRecorders
	this.auditDeliveries, this.recordingRepositories = owner.auditDeliveries, owner.recordingRepositories
	this.recordingTargets, this.recordingDeliveries = owner.recordingTargets, owner.recordingDeliveries
	this.enabledAuditlogs, this.auditlogStates = owner.enabledAuditlogs, owner.auditlogStates
	this.unauthenticatedAudit = owner.unauthenticatedAudit
	return this.bindFlowAudit()
}

func (this *service) bindFlowAudit() error {
	this.flowAuditRecorders = make(map[configuration.FlowName]audit.Recorder, len(this.Configuration.Flows))
	this.flowAuditlogs = make(map[configuration.FlowName]configuration.AuditlogName, len(this.Configuration.Flows))
	for _, flow := range this.Configuration.Flows {
		recorder := this.auditRecorders[flow.Auditlog]
		if recorder == nil {
			if flow.Auditlog != "" {
				return fmt.Errorf("flow %q references unavailable auditlog %q", flow.Name, flow.Auditlog)
			}
			recorder = audit.NewNoopRecorder()
		}
		this.flowAuditRecorders[flow.Name], this.flowAuditlogs[flow.Name] = recorder, flow.Auditlog
	}
	return nil
}

// closeGeneration never stops global admission or closes borrowed resources.
func (this *service) closeGeneration() error {
	this.generationCloseOnce.Do(func() {
		this.generationCloseErr = this.stopGenerationWork()
		if this.providerCancel != nil {
			this.providerCancel()
		}
		common.KeepCloseError(&this.generationCloseErr, this.environments)
		common.KeepCloseError(&this.generationCloseErr, this.authorizer)
		common.KeepCloseError(&this.generationCloseErr, this.managementApplication)
	})
	return this.generationCloseErr
}

func (this *runtimeResources) close(flush bool) error {
	this.closeOnce.Do(func() {
		this.preparations.stop()
		this.handlers.stop()
		this.cancel()
		this.mutex.Lock()
		listeners := this.listeners
		this.mutex.Unlock()
		if listeners != nil {
			listeners.cancel(context.Canceled)
		}
		this.owner.runtime.stop()
		this.preparations.waitUntilDrained()
		this.closeErr = goerrors.Join(this.closeErr, this.owner.oidcRefresh.Close(), this.owner.houseKeeper.Close())
		if this.owner.sshTunnel != nil {
			this.closeErr = goerrors.Join(this.closeErr, this.owner.sshTunnel.Close())
		}
		if this.owner.web != nil {
			this.closeErr = goerrors.Join(this.closeErr, this.owner.web.Close())
		}
		if this.owner.https != nil {
			this.closeErr = goerrors.Join(this.closeErr, this.owner.https.Close())
		}
		this.closeErr = goerrors.Join(this.closeErr, closeSessionConnections(this.owner.runtime.allConnections()))
		this.mutex.Lock()
		views := make([]*service, 0, len(this.views))
		for svc := range this.views {
			views = append(views, svc)
		}
		this.mutex.Unlock()
		// Stop task admission before releasing session ownership. The shared
		// background loops have already been joined above.
		for _, svc := range views {
			this.owner.runtime.discard(svc.generation)
			this.closeErr = goerrors.Join(this.closeErr, svc.stopGenerationWork())
		}
		this.closeErr = goerrors.Join(this.closeErr, this.owner.stopGenerationWork())
		this.handlers.waitUntilDrained()
		if listeners != nil {
			<-listeners.done
		}
		this.closeErr = goerrors.Join(this.closeErr, this.owner.closeTLS())
		this.owner.runtime.forgetSessions()
		this.cleanup.Wait()
		this.closeErr = goerrors.Join(this.closeErr, this.owner.closeGeneration(), this.cleanupErr)
		this.closeErr = goerrors.Join(this.closeErr, this.owner.closeSharedResources(flush))
	})
	return this.closeErr
}

func (this *runtimeResources) restartSections(snapshot *configuration.Snapshot) []string {
	before, after := this.owner.Configuration, snapshot.Configuration()
	ssh := after.Ssh
	ssh.Enabled, ssh.Addresses = before.Ssh.Enabled, before.Ssh.Addresses
	http := after.Http
	if before.Http != nil && after.Http != nil {
		copyOfHTTP := *after.Http
		copyOfHTTP.Addresses = before.Http.Addresses
		if this.owner.https != nil && !before.Http.IsAcmeTlsAlpnOnly() && !after.Http.IsAcmeTlsAlpnOnly() {
			// The existing endpoint and certificate state survive disabling.
			// Adding the HTTP component for the first time still needs restart.
			copyOfHTTP.Enabled = before.Http.Enabled
		}
		http = &copyOfHTTP
	}
	var result []string
	for _, section := range this.owner.generation.snapshot.ChangesTo(snapshot).Sections {
		if section == "ssh" && before.Ssh.IsEqualTo(ssh) || section == "http" && before.Http.IsEqualTo(http) {
			continue
		}
		result = append(result, section)
	}
	return result
}

// This is the only provider construction path, for startup and reload alike.
// It deliberately excludes process resources and background worker startup.
func (this *service) prepareGenerationProviders(ctx context.Context) (err error) {
	this.managementApplication, err = cli.NewApplication[clibase.NoOptions](this.Version, "Bifröst SSH management.", nil).Create()
	if err != nil {
		return err
	}
	this.knownFlows = make(map[configuration.FlowName]struct{}, len(this.Configuration.Flows))
	for _, flow := range this.Configuration.Flows {
		this.knownFlows[flow.Name] = struct{}{}
	}
	resolve := func(source interface{ MarshalTexts() ([][]byte, error) }) ([]string, error) {
		texts, err := source.MarshalTexts()
		if err != nil {
			return nil, err
		}
		result := make([]string, len(texts))
		for index, text := range texts {
			result[index] = string(text)
		}
		return result, nil
	}
	if this.resolvedSshKeysExchanges, err = resolve(this.Configuration.Ssh.Keys.Exchanges); err != nil {
		return err
	}
	if this.resolvedSshMessagesAuthentications, err = resolve(this.Configuration.Ssh.Messages.Authentications); err != nil {
		return err
	}
	if this.resolvedSshMessagesCiphers, err = resolve(this.Configuration.Ssh.Messages.Ciphers); err != nil {
		return err
	}
	authorizerContext := authorization.WithOidcSessionLocks(ctx, &this.resources.oidcLocks)
	if web := this.resources.owner.web; web != nil {
		authorizerContext = authorization.WithOidcBrowser(authorizerContext, web)
	}
	authorizer, err := authorization.NewAuthorizerFacadeWithObserver(authorizerContext, &this.Configuration.Flows, this.observeFlowAuthorization)
	if err != nil {
		return err
	}
	this.authorizer, this.authorizerDiscovery = authorizer, authorizer
	this.houseKeeper.prepare(this)
	this.oidcRefresh.prepare(this)
	this.environments, err = this.resources.environments.NewWithManagement(ctx, &this.Configuration.Flows, this)
	return err
}

func (this *service) stopGenerationWork() error {
	this.workCloseOnce.Do(func() {
		if this.cancelTerminals != nil {
			this.cancelTerminals()
		}
		if this.terminalAdmissions != nil {
			this.terminalAdmissions.stop()
			this.terminalAdmissions.waitUntilDrained()
		}
		if this.connectionLifecycle != nil {
			this.connectionLifecycle.stop()
		}
		if this.executions != nil {
			this.executions.stop()
		}
		if this.resources == nil {
			this.workCloseErr = goerrors.Join(this.oidcRefresh.Close(), this.houseKeeper.Close())
		}
		if this.executions != nil {
			this.executions.waitUntilDrained()
		}
	})
	return this.workCloseErr
}

func (this *runtimeResources) reserveSSHKeys(ctx context.Context, svc *service) error {
	keys, err := loadStaticPrivateKeysForAuditEncryption(ctx, svc.Configuration.Flows, this.hostKeys)
	if err != nil {
		return err
	}
	this.keysMutex.Lock()
	defer this.keysMutex.Unlock()
	var publicKeys []crypto.PublicKey
	forbiddenKeys := append(append([]crypto.PublicKey(nil), this.owner.auditProtectedKeys...), this.tlsKeys...)
	for _, key := range keys {
		public := key.PublicKey()
		for _, forbidden := range forbiddenKeys {
			if public.IsEqualTo(forbidden) {
				return fmt.Errorf("SSH environment key must be distinct from audit signing, SFTP, encryption and TLS keys")
			}
		}
		publicKeys = append(publicKeys, public)
	}
	this.sshKeys[svc] = publicKeys
	return nil
}

func (this *runtimeResources) validateTLSKey(key stdcrypto.PublicKey) error {
	public, err := crypto.PublicKeyFromSdk(key)
	if err != nil {
		return fmt.Errorf("cannot inspect HTTPS key identity")
	}
	this.keysMutex.Lock()
	defer this.keysMutex.Unlock()
	for _, keys := range this.sshKeys {
		for _, other := range keys {
			if public.IsEqualTo(other) {
				return fmt.Errorf("HTTPS/ACME key must be distinct from SSH environment keys of prepared and retained generations")
			}
		}
	}
	for _, other := range this.tlsKeys {
		if public.IsEqualTo(other) {
			return nil
		}
	}
	this.tlsKeys = append(this.tlsKeys, public)
	return nil
}
