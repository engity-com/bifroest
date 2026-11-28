package service

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"io/fs"
	gonet "net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	clibase "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	cliCommon "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/imp"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

var (
	connectionCtxKey          = struct{ uint64 }{83439637}
	authorizationCtxKey       = struct{ uint64 }{10282643}
	handshakeKeyCtxKey        = struct{ uint64 }{30072498}
	connectionLifecycleCtxKey = struct{ uint64 }{23424012}
)

const remoteAuditDeliveryShutdownTimeout = 5 * time.Second

type Service struct {
	Configuration configuration.Configuration
	Version       sys.Version
	Watch         configuration.WatchMode

	Logger log.Logger
}

// Run starts a service with the configuration selected by the executable CLI.
func Run(ctx context.Context, conf configuration.Configuration, version sys.Version) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return (&Service{Configuration: conf, Version: version, Watch: cliCommon.ServiceRunOptionsFromContext(ctx).Watch}).Run(ctx)
}

func (this *Service) isProblematicError(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, candidate := range joined.Unwrap() {
			if this.isProblematicError(candidate) {
				return true
			}
		}
		return false
	}
	if wrapped := goerrors.Unwrap(err); wrapped != nil {
		return this.isProblematicError(wrapped)
	}
	if errors.Is(err, essh.ErrGracefulShutdownTimeout) {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, gonet.ErrClosed) {
		return false
	}
	return true
}

func (this *Service) Run(ctx context.Context) (rErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := this.Watch.Validate(); err != nil {
		return err
	}
	if this.Watch.IsEnabled() && this.Configuration.Filename == "" {
		return fmt.Errorf("--watch requires a configuration file source")
	}

	if msg, err := this.Configuration.StartMessage.Render(noopContext{}); err != nil {
		return err
	} else if msg != "" {
		for _, line := range strings.Split(msg, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				log.Warn(line)
			}
		}
	}

	if err := this.Configuration.Validate(); err != nil {
		return err
	}
	monitor, err := newServiceMonitoring(this.Configuration, this.Watch.IsEnabled())
	if err != nil {
		return errors.Config.Newf("cannot prepare monitoring: %w", err)
	}
	if monitor != nil {
		monitor.reload.enabled.Set(monitoringBool(this.Watch.IsEnabled()))
	}
	if monitor != nil && monitor.endpoint != nil {
		if !this.Configuration.Monitoring.Tls.IsEnabled() {
			if err := monitor.endpoint.Start(func(err error) { this.logger().WithError(err).Error("monitoring listener failed") }); err != nil {
				return err
			}
		}
		defer common.KeepCloseError(&rErr, monitor.endpoint)
	}
	svc, err := this.prepareContextWithMonitoring(ctx, monitor)
	if err != nil {
		return err
	}
	this.warnOnManagementAccess()
	closeService := true
	defer func() {
		if closeService {
			common.KeepCloseError(&rErr, svc)
		}
	}()

	shutdown, err := svc.runListeners(ctx, nil)
	rErr = err
	gracefulShutdownTimeout := this.Configuration.Ssh.GracefulShutdownTimeout.Native()
	handlerDrainTimeout := remainingGracefulShutdownTimeout(gracefulShutdownTimeout, shutdown.startedAt, time.Now())
	if shutdown.forced {
		handlerDrainTimeout = 0
	}
	if !svc.handlerLifecycle().wait(handlerDrainTimeout) {
		drainErr := fmt.Errorf("SSH connection handlers did not finish within the graceful shutdown timeout of %s", gracefulShutdownTimeout)
		this.logger().WithError(drainErr).Warn("delaying service cleanup until SSH connection handlers finish")
		if this.isProblematicError(shutdown.cause) {
			rErr = goerrors.Join(rErr, drainErr)
		}
		closeService = false
		go func() {
			svc.handlerLifecycle().waitUntilDrained()
			if err := svc.Close(); err != nil {
				this.logger().WithError(err).Error("cannot close service after SSH connection handlers finished")
			}
		}()
	}

	return
}

func remainingGracefulShutdownTimeout(total time.Duration, startedAt, now time.Time) time.Duration {
	if total <= 0 || startedAt.IsZero() {
		return total
	}
	remaining := total - now.Sub(startedAt)
	if remaining <= 0 {
		return 0
	}
	return remaining
}

func (this *Service) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("service")
}

func (this *Service) prepare() (svc *service, err error) {
	return this.prepareContext(context.Background())
}

func (this *Service) prepareContext(ctx context.Context) (svc *service, err error) {
	return this.prepareContextWithMonitoring(ctx, nil)
}

func (this *Service) prepareContextWithMonitoring(ctx context.Context, monitor *serviceMonitoring) (svc *service, err error) {
	fail := func(err error) (*service, error) {
		return nil, fmt.Errorf("cannot prepare service: %w", err)
	}
	snapshot, err := configuration.NewSnapshot(this.Configuration)
	if err != nil {
		return fail(err)
	}
	sourceConfiguration := snapshot.Configuration()
	// Runtime objects must never borrow the caller's mutable configuration.
	owner := *this
	owner.Configuration = snapshot.Configuration()
	this = &owner
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := validateRuntimePaths(&this.Configuration); err != nil {
		return fail(err)
	}
	snapshot, err = configuration.NewSnapshot(this.Configuration)
	if err != nil {
		return fail(err)
	}

	svc = &service{
		Service:             this,
		monitoring:          monitor,
		connectionLifecycle: newConnectionLifecycle(),
		executions:          newConnectionLifecycle(),
		terminalAdmissions:  newConnectionLifecycle(),
	}
	svc.terminalContext, svc.cancelTerminals = context.WithCancel(context.Background())
	svc.runtime = newRuntimeGenerations(snapshot, this.Watch)
	svc.resources = newRuntimeResources(svc)
	svc.generationClosed = make(chan struct{})
	svc.runtime.activeConnections = &svc.activeConnections
	svc.generation = svc.runtime.initial
	svc.sessionConnections.runtime = svc.runtime
	resourcesOwnedByService := false
	defer func(prepared *service) {
		if !resourcesOwnedByService {
			err = goerrors.Join(err, prepared.close(false))
		}
	}(svc)
	if this.Watch.IsEnabled() {
		svc.configurationReloader, err = configuration.NewFileReloader(sourceConfiguration, svc.applyConfigurationReload)
		if err != nil {
			return fail(err)
		}
	}
	hostSigners, err := this.loadHostPrivateKeys()
	if err != nil {
		return fail(err)
	}
	svc.resources.hostKeys = hostSigners
	if err := this.prepareAudit(ctx, svc, hostSigners); err != nil {
		return fail(err)
	}
	if err := svc.prepareHTTPS(); err != nil {
		return fail(err)
	}
	if monitor != nil && monitor.endpoint != nil && this.Configuration.Monitoring.Tls.IsEnabled() {
		if err := monitor.endpoint.Start(func(err error) { this.logger().WithError(err).Error("monitoring listener failed") }); err != nil {
			return fail(err)
		}
	}
	if err := this.logCertificateAuthorities(hostSigners); err != nil {
		return fail(err)
	}

	if svc.alternatives, err = alternatives.NewProvider(ctx, this.Version, &this.Configuration.Alternatives); err != nil {
		return fail(err)
	}
	if svc.imp, err = imp.NewImp(ctx, hostSigners[0]); err != nil {
		return fail(err)
	}
	sessions, err := session.NewFacadeRepository(ctx, &this.Configuration.Session)
	if err != nil {
		return fail(err)
	}
	svc.sessions = sessions
	previousRuntime, err := svc.openRuntimePersistence(ctx)
	if err != nil {
		return fail(err)
	}
	svc.resources.environments = environment.NewFacadeFactory(svc.alternatives, svc.imp, hostSigners, svc.sessions)
	if err := svc.prepareGenerationProviders(ctx); err != nil {
		return fail(err)
	}
	if err := svc.initializeRuntimePersistence(ctx, previousRuntime); err != nil {
		return fail(err)
	}
	if err := svc.registerRuntimeSessions(ctx); err != nil {
		return fail(err)
	}
	// Publish immutable manager state before housekeeping can stop or inspect
	// refresh workers. Persisted-session discovery still follows housekeeping.
	svc.oidcRefresh.start(svc)
	if err = svc.houseKeeper.init(svc); err != nil {
		return fail(err)
	}
	if err := this.prepareServer(ctx, svc, hostSigners); err != nil {
		return fail(err)
	}
	for _, auditlog := range this.Configuration.Auditlogs {
		if delivery := svc.auditDeliveries[auditlog.Name]; delivery != nil && !svc.auditlogDisabled(auditlog.Name) {
			if startErr := delivery.Start(); startErr != nil {
				if err := svc.handleAuditlogFailure(auditlog.Name, "remote delivery", startErr); err != nil {
					return fail(err)
				}
			}
		}
	}
	for _, auditlog := range this.Configuration.Auditlogs {
		if delivery := svc.recordingDeliveries[auditlog.Name]; delivery != nil && !svc.auditlogDisabled(auditlog.Name) {
			if startErr := delivery.Start(); startErr != nil {
				if err := svc.handleAuditlogFailure(auditlog.Name, "Recording delivery", startErr); err != nil {
					return fail(err)
				}
			}
		}
	}
	if err := svc.oidcRefresh.discover(); err != nil {
		return fail(err)
	}

	if monitor != nil {
		monitor.service.Store(svc)
		svc.sessionConnections.observeAges = true
	}
	resourcesOwnedByService = true
	svc.resources.track(svc)
	return svc, nil
}

func (this *Service) prepareAudit(ctx context.Context, svc *service, hostSigners []crypto.PrivateKey) (err error) {
	svc.auditIdentities = make(map[configuration.AuditlogName]*audit.Identity, len(this.Configuration.Auditlogs))
	svc.auditRecorders = make(map[configuration.AuditlogName]audit.Recorder, len(this.Configuration.Auditlogs))
	svc.auditDeliveries = make(map[configuration.AuditlogName]*audit.RemoteDelivery, len(this.Configuration.Auditlogs))
	svc.recordingRepositories = make(map[configuration.AuditlogName]*sessionRecordingRepository, len(this.Configuration.Auditlogs))
	svc.recordingTargets = make(map[configuration.AuditlogName]*audit.RemoteArtifactTargets, len(this.Configuration.Auditlogs))
	svc.recordingDeliveries = make(map[configuration.AuditlogName]*audit.RemoteArtifactDelivery, len(this.Configuration.Auditlogs))
	svc.flowAuditRecorders = make(map[configuration.FlowName]audit.Recorder, len(this.Configuration.Flows))
	svc.flowAuditlogs = make(map[configuration.FlowName]configuration.AuditlogName, len(this.Configuration.Flows))
	svc.enabledAuditlogs = make(map[configuration.AuditlogName]bool, len(this.Configuration.Auditlogs))
	svc.auditlogStates = make(map[configuration.AuditlogName]*auditlogRuntimeState, len(this.Configuration.Auditlogs))
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		svc.enabledAuditlogs[auditlog.Name] = true
		svc.auditlogStates[auditlog.Name] = &auditlogRuntimeState{policy: auditlog.FailurePolicy}
		svc.auditIdentities[auditlog.Name] = nil
	}

	serverPrivateKeys := hostSigners
	if this.Configuration.Http.IsListenerEnabled() || len(this.Configuration.Auditlogs) > 0 || this.Configuration.Monitoring.IsEnabled() && this.Configuration.Monitoring.Tls.IsEnabled() {
		serverPrivateKeys, err = loadStaticPrivateKeysForAuditEncryption(ctx, this.Configuration.Flows, hostSigners)
		if err != nil {
			return err
		}
	}
	for _, key := range serverPrivateKeys {
		svc.httpsForbiddenKeys = append(svc.httpsForbiddenKeys, key.PublicKey())
	}
	sftpIdentityPublicKeysByAuditlog := make(map[configuration.AuditlogName][]crypto.PublicKey, len(this.Configuration.Auditlogs))
	var failedSftpIdentityPublicKeys []crypto.PublicKey
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		keys, identityErr := loadStaticSftpIdentityPublicKeysForAuditEncryption(auditlog)
		if identityErr != nil {
			failedSftpIdentityPublicKeys = append(failedSftpIdentityPublicKeys, keys...)
			if err := svc.handleAuditlogFailure(auditlog.Name, "SFTP identities", identityErr); err != nil {
				return err
			}
			continue
		}
		sftpIdentityPublicKeysByAuditlog[auditlog.Name] = keys
	}
	var disabledSftpIdentityPublicKeys []crypto.PublicKey
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		keys, loadErr := loadExistingDisabledSftpIdentityPublicKeys(auditlog, this.Configuration.Auditlogs)
		if loadErr != nil {
			return loadErr
		}
		disabledSftpIdentityPublicKeys = append(disabledSftpIdentityPublicKeys, keys...)
	}
	availableAuditIdentityKeys := make(map[configuration.AuditlogName]crypto.PublicKey, len(this.Configuration.Auditlogs))
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		if svc.auditlogDisabled(auditlog.Name) {
			continue
		}
		identity, identityErr := audit.EnsureIdentityWithAuditlogs(auditlog, this.Configuration.Auditlogs)
		if identityErr != nil {
			if auditlog.Recording.Enabled {
				identityErr = fmt.Errorf("cannot open Recording repository of auditlog %q: %w", auditlog.Name, identityErr)
			}
			if err := svc.handleAuditlogFailure(auditlog.Name, "identity", identityErr); err != nil {
				return err
			}
			continue
		}
		availableAuditIdentityKeys[auditlog.Name] = identity.PublicKey()
		if identityErr := identity.ValidateDedicatedFrom(serverPrivateKeys); identityErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "identity", identityErr); err != nil {
				return err
			}
			continue
		}
		svc.auditIdentities[auditlog.Name] = identity
	}
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		if availableAuditIdentityKeys[auditlog.Name] != nil || !svc.auditlogDisabled(auditlog.Name) {
			continue
		}
		key, loadErr := audit.LoadExistingIdentityPublicKey(auditlog.IdentityFile)
		if loadErr != nil {
			return fmt.Errorf("cannot verify identity of auditlog %q: %w", auditlog.Name, loadErr)
		}
		if key != nil {
			availableAuditIdentityKeys[auditlog.Name] = key
		}
	}
	sftpIdentityPublicKeys := append(failedSftpIdentityPublicKeys, disabledSftpIdentityPublicKeys...)
	for _, keys := range sftpIdentityPublicKeysByAuditlog {
		sftpIdentityPublicKeys = append(sftpIdentityPublicKeys, keys...)
	}
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		identity := svc.auditIdentities[auditlog.Name]
		if identity == nil || svc.auditlogDisabled(auditlog.Name) {
			continue
		}
		if identityErr := identity.ValidateDedicatedFromPublicKeys(sftpIdentityPublicKeys); identityErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "identity", identityErr); err != nil {
				return err
			}
			delete(svc.auditIdentities, auditlog.Name)
		}
	}
	auditIdentityPublicKeys := make([]crypto.PublicKey, 0, len(availableAuditIdentityKeys))
	for _, key := range availableAuditIdentityKeys {
		auditIdentityPublicKeys = append(auditIdentityPublicKeys, key)
	}
	svc.httpsForbiddenKeys = append(svc.httpsForbiddenKeys, auditIdentityPublicKeys...)
	svc.httpsForbiddenKeys = append(svc.httpsForbiddenKeys, sftpIdentityPublicKeys...)
	svc.auditProtectedKeys = append(svc.auditProtectedKeys, auditIdentityPublicKeys...)
	svc.auditProtectedKeys = append(svc.auditProtectedKeys, sftpIdentityPublicKeys...)
	resolvedEncryptionPublicKeys := make(map[configuration.AuditlogName]crypto.PublicKeys, len(this.Configuration.Auditlogs))
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		// Keep available configured recipients protected even when best-effort
		// disabled this log earlier. Reloaded providers must not reuse them.
		encryptionPublicKey, encryptionErr := audit.ResolveEncryptionPublicKey(auditlog.EncryptionPublicKey, auditlog.EncryptionPublicKeyFile)
		if err := encryptionPublicKey.ForEach(func(_ int, key gossh.PublicKey, _ string) (bool, error) {
			public, err := crypto.PublicKeyFromSsh(key)
			if err != nil {
				return false, err
			}
			svc.auditProtectedKeys = append(svc.auditProtectedKeys, public)
			return true, nil
		}); err != nil {
			return fmt.Errorf("cannot inspect configured audit encryption recipients: %w", err)
		}
		if svc.auditlogDisabled(auditlog.Name) {
			continue
		}
		if encryptionErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "encryption", encryptionErr); err != nil {
				return err
			}
			continue
		}
		if encryptionErr := audit.ValidateEncryptionRecipientDedicatedFrom(encryptionPublicKey, serverPrivateKeys); encryptionErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "encryption", encryptionErr); err != nil {
				return err
			}
			continue
		}
		if encryptionErr := audit.ValidateEncryptionRecipientDedicatedFromPublicKeys(encryptionPublicKey, sftpIdentityPublicKeys); encryptionErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "encryption", encryptionErr); err != nil {
				return err
			}
			continue
		}
		if encryptionErr := audit.ValidateEncryptionRecipientDedicatedFromPublicKeys(encryptionPublicKey, auditIdentityPublicKeys); encryptionErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "encryption", encryptionErr); err != nil {
				return err
			}
			continue
		}
		resolvedEncryptionPublicKeys[auditlog.Name] = encryptionPublicKey
		if err := encryptionPublicKey.ForEach(func(_ int, key gossh.PublicKey, _ string) (bool, error) {
			public, err := crypto.PublicKeyFromSsh(key)
			if err != nil {
				return false, err
			}
			svc.httpsForbiddenKeys = append(svc.httpsForbiddenKeys, public)
			return true, nil
		}); err != nil {
			return fmt.Errorf("cannot inspect audit encryption recipients: %w", err)
		}
	}
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		if !auditlog.Recording.Enabled || svc.auditlogDisabled(auditlog.Name) {
			continue
		}
		targetConfigurations := sessionRecordingTargetConfigurations(auditlog)
		var targets *audit.RemoteArtifactTargets
		if len(targetConfigurations) > 0 {
			var targetErr error
			targets, targetErr = audit.NewRemoteArtifactTargets(ctx, auditlog.Name, targetConfigurations)
			if targetErr != nil {
				failure := fmt.Errorf("cannot prepare Recording targets of auditlog %q: %w", auditlog.Name, targetErr)
				if err := svc.handleAuditlogFailure(auditlog.Name, "recording targets", failure); err != nil {
					return err
				}
				continue
			}
		}
		repository, repositoryErr := newSessionRecordingRepository(ctx, auditlog.Recording, svc.auditIdentities[auditlog.Name], resolvedEncryptionPublicKeys[auditlog.Name], auditlog.Name, targets, true)
		if repositoryErr != nil {
			failure := fmt.Errorf("cannot open Recording repository of auditlog %q: %w", auditlog.Name, repositoryErr)
			if targets != nil {
				failure = goerrors.Join(failure, targets.Close())
			}
			if err := svc.handleAuditlogFailure(auditlog.Name, "recording repository", failure); err != nil {
				return err
			}
			continue
		}
		if targets == nil {
			if validateErr := repository.receipts.ValidateDeliveryTargets(ctx, repository, nil); validateErr != nil {
				failure := fmt.Errorf("cannot validate Recording delivery of auditlog %q: %w", auditlog.Name, goerrors.Join(validateErr, repository.Close()))
				if err := svc.handleAuditlogFailure(auditlog.Name, "recording delivery", failure); err != nil {
					return err
				}
				continue
			}
		}
		var delivery *audit.RemoteArtifactDelivery
		if targets != nil {
			auditor := &sessionRecordingDeliveryAuditor{service: svc, auditlog: auditlog.Name, repository: repository}
			var deliveryErr error
			delivery, deliveryErr = audit.NewRemoteArtifactDelivery(ctx, filepath.Join(auditlog.Recording.Directory, "sealed"), repository, repository.receipts, targets, auditor)
			if deliveryErr != nil {
				failure := fmt.Errorf("cannot prepare Recording delivery of auditlog %q: %w", auditlog.Name, goerrors.Join(deliveryErr, repository.Close(), targets.Close()))
				if err := svc.handleAuditlogFailure(auditlog.Name, "recording delivery", failure); err != nil {
					return err
				}
				continue
			}
		}
		svc.recordingRepositories[auditlog.Name] = repository
		svc.recordingRepositoryOrder = append(svc.recordingRepositoryOrder, auditlog.Name)
		if targets != nil {
			svc.recordingTargets[auditlog.Name] = targets
			svc.recordingTargetOrder = append(svc.recordingTargetOrder, auditlog.Name)
			svc.recordingDeliveries[auditlog.Name] = delivery
			svc.recordingDeliveryOrder = append(svc.recordingDeliveryOrder, delivery)
		}
	}
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		if svc.auditlogDisabled(auditlog.Name) {
			svc.auditRecorders[auditlog.Name] = audit.NewNoopRecorder()
			continue
		}
		identity := svc.auditIdentities[auditlog.Name]
		recorderConfiguration := *auditlog
		recorderConfiguration.EncryptionPublicKey = resolvedEncryptionPublicKeys[auditlog.Name]
		recorderConfiguration.EncryptionPublicKeyFile = ""
		recorder, recorderErr := audit.NewRecorder(&recorderConfiguration, identity)
		if recorderErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "journal", recorderErr); err != nil {
				return err
			}
			svc.auditRecorders[auditlog.Name] = audit.NewNoopRecorder()
			continue
		}
		policyRecorder := audit.Recorder(&failurePolicyAuditRecorder{service: svc, auditlog: auditlog.Name, delegate: recorder})
		if len(auditlog.Targets) > 0 {
			delivery, deliveryErr := audit.NewRemoteDelivery(ctx, auditlog, identity)
			if deliveryErr != nil {
				failure := goerrors.Join(deliveryErr, policyRecorder.Close())
				if err := svc.handleAuditlogFailure(auditlog.Name, "remote delivery", failure); err != nil {
					return err
				}
				svc.auditRecorders[auditlog.Name] = audit.NewNoopRecorder()
				continue
			}
			svc.auditDeliveries[auditlog.Name] = delivery
			svc.auditDeliveryOrder = append(svc.auditDeliveryOrder, delivery)
		}
		svc.auditRecorders[auditlog.Name] = policyRecorder
		svc.auditRecorderOrder = append(svc.auditRecorderOrder, policyRecorder)
	}
	if err := svc.replaySessionRecordingLifecycles(ctx); err != nil {
		return err
	}
	if err := svc.bindFlowAudit(); err != nil {
		return err
	}
	svc.unauthenticatedAudit = newUnauthenticatedAuditLimiter(this.Configuration.Ssh.UnauthenticatedAudit)
	if svc.monitoring != nil {
		svc.unauthenticatedAudit.onSuppressed = svc.monitoring.suppress
	}
	return nil
}

func (this *Service) prepareServer(_ context.Context, svc *service, hostPrivateKeys []crypto.PrivateKey) (err error) {
	sshConfig := &svc.Configuration.Ssh
	svc.forwardHandler.ListenCallback = svc.listenReverseTCP
	this.configureServer(svc, &svc.server, hostPrivateKeys)
	if sshConfig.ProxyProtocol {
		svc.server.ProxyProtocol = new(essh.ProxyProtocolConfig)
	}
	// Construct separately, never copy an ssh.Server (including its runtime locks).
	this.configureServer(svc, &svc.tunnelServer, hostPrivateKeys)
	return nil
}

func (this *Service) configureServer(svc *service, server *essh.Server, hostPrivateKeys []crypto.PrivateKey) {
	sshConfig := &svc.Configuration.Ssh

	server.Logger = svc.Service.logger()
	server.RequireHostSigners = true
	server.RequireClientAuth = true
	server.HandshakeTimeout = new(sshConfig.HandshakeTimeout.Native())
	server.IdleTimeout = new(time.Duration(0)) // handled by service's connection
	server.MaxTimeout = new(time.Duration(0))  // handled by service's connection
	server.SessionRequestTimeout = new(sshConfig.SessionRequestTimeout.Native())
	server.MaxStartups = &essh.MaxStartupsConfig{
		Start: int(sshConfig.MaxStartupsStart),
		Rate:  int(sshConfig.MaxStartupsRate),
		Full:  int(sshConfig.MaxStartupsFull),
	}
	server.MaxSessionsPerConnection = new(int(sshConfig.MaxSessionsPerConnection))
	server.MaxChannelsPerConnection = new(int(sshConfig.MaxChannelsPerConnection))
	server.MaxReverseForwardsPerConnection = new(int(sshConfig.MaxReverseForwardsPerConnection))
	server.MaxConnections = new(0)
	server.MaxChannels = new(int(sshConfig.MaxChannels))
	server.MaxReverseForwards = new(int(sshConfig.MaxReverseForwards))
	if svc.monitoring != nil {
		transport := "ssh"
		if server == &svc.tunnelServer {
			transport = "ssh_tunnel"
		}
		server.LimitRejectedCallback = func(reason essh.LimitRejectionReason) error {
			svc.monitoring.sshLimitRejected(transport, reason)
			return nil
		}
	}
	server.GracefulShutdownHandler = essh.NewGracefulShutdownTimeoutHandler(sshConfig.GracefulShutdownTimeout.Native())
	server.ErrorHandler = svc.handleSshError
	svc.configureSshDispatch(server)
	server.HostSigners = make([]essh.Signer, len(hostPrivateKeys))
	for i, v := range hostPrivateKeys {
		server.HostSigners[i] = v.ToSsh()
	}
}

func (this *service) handleSshError(
	ctx context.Context,
	scope essh.ErrorScope,
	operation essh.ErrorOperation,
	err error,
	respond essh.ErrorResponder,
	next essh.ErrorHandler,
) (bool, error) {
	if scope == essh.ErrorScopeConnection && operation == essh.ErrorOperationHandshake && isExpectedSshHandshakeEnd(err) {
		this.logger().
			WithError(err).
			With("scope", scope.String()).
			With("operation", operation.String()).
			Debug("SSH connection ended during handshake")
		return false, nil
	}
	return next(ctx, scope, operation, err, respond, next)
}

func isExpectedSshHandshakeEnd(err error) bool {
	if goerrors.Is(err, errInteractiveClientDisconnect) {
		return true
	}
	if errors.IsType(err, errors.System) {
		return false
	}
	if isSshTransportDisconnect(err) {
		return true
	}
	var authErr *gossh.ServerAuthError
	return goerrors.As(err, &authErr) && authErr != nil && len(authErr.Errors) == 1 && goerrors.Is(authErr.Errors[0], gossh.ErrNoAuth)
}

func isSshTransportDisconnect(err error) bool {
	return sys.IsClosedError(err) || goerrors.Is(err, io.ErrUnexpectedEOF) || goerrors.Is(err, syscall.ECONNRESET)
}

func (this *Service) loadHostPrivateKeys() ([]crypto.PrivateKey, error) {
	return EnsureHostPrivateKeys(&this.Configuration)
}

func loadStaticPrivateKeysForAuditEncryption(ctx context.Context, flows configuration.Flows, hostKeys []crypto.PrivateKey) ([]crypto.PrivateKey, error) {
	result := append([]crypto.PrivateKey(nil), hostKeys...)
	for index := range flows {
		flow := &flows[index]
		sshEnvironment, ok := flow.Environment.V.(*configuration.EnvironmentSsh)
		if !ok {
			continue
		}
		if sshEnvironment.Certificate != nil {
			identity, _, err := environment.EnsureSshCertificateIdentityContext(ctx, flow)
			if err != nil {
				return nil, err
			}
			authority, _, err := environment.EnsureSshCertificateAuthorityContext(ctx, flow)
			if err != nil {
				return nil, err
			}
			result = append(result, identity, authority)
			continue
		}
		for _, configuredPath := range sshEnvironment.IdentityFiles {
			if !configuredPath.IsHardCoded() {
				continue
			}
			path := strings.TrimSpace(configuredPath.String())
			key, err := crypto.EnsureKeyFileContext(ctx, path, nil, nil)
			if err != nil {
				return nil, fmt.Errorf("cannot load static SSH identity of flow %q: %w", flow.Name, err)
			}
			result = append(result, key)
		}
	}
	return result, nil
}

func loadStaticSftpIdentityPublicKeysForAuditEncryption(auditlog *configuration.Auditlog) ([]crypto.PublicKey, error) {
	var result []crypto.PublicKey
	var resultErr error
	for targetIndex := range auditlog.Targets {
		target := &auditlog.Targets[targetIndex]
		sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
		if !ok || len(sftp.IdentityFiles) == 0 {
			continue
		}
		keys, err := audit.LoadSftpIdentityPublicKeys(sftp.IdentityFiles)
		result = append(result, keys...)
		if err != nil {
			resultErr = goerrors.Join(resultErr, fmt.Errorf("cannot load static SFTP identities of target %q in auditlog %q: %w", target.Name, auditlog.Name, err))
		}
	}
	if !auditlog.Recording.Enabled {
		return result, resultErr
	}
	for targetIndex := range auditlog.Recording.Targets.Configured() {
		target := &auditlog.Recording.Targets.Targets[targetIndex]
		sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
		if !ok || len(sftp.IdentityFiles) == 0 {
			continue
		}
		keys, err := audit.LoadSftpIdentityPublicKeys(sftp.IdentityFiles)
		result = append(result, keys...)
		if err != nil {
			resultErr = goerrors.Join(resultErr, fmt.Errorf("cannot load static SFTP identities of Recording target %q in auditlog %q: %w", target.Name, auditlog.Name, err))
		}
	}
	return result, resultErr
}

func loadExistingDisabledSftpIdentityPublicKeys(auditlog *configuration.Auditlog, auditlogs configuration.Auditlogs) ([]crypto.PublicKey, error) {
	var result []crypto.PublicKey
	var resultErr error
	loadTargets := func(targets configuration.AuditlogTargets, kind string) {
		for _, target := range targets {
			sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
			if !ok || sftp == nil {
				continue
			}
			for _, path := range sftp.IdentityFiles {
				resolved, err := sys.CanonicalPath(path)
				if err != nil {
					resultErr = goerrors.Join(resultErr, fmt.Errorf("cannot resolve static SFTP identity file %q of %s %q in auditlog %q: %w", path, kind, target.Name, auditlog.Name, err))
					continue
				}
				overlaps := false
				for _, other := range auditlogs {
					if runtimePathsOverlap(resolved, other.IdentityFile) {
						resultErr = goerrors.Join(resultErr, errors.Config.Newf("auditlog %q %s %q static SFTP identity file %q overlaps auditlog %q identity file", auditlog.Name, kind, target.Name, path, other.Name))
						overlaps = true
						break
					}
				}
				if overlaps {
					continue
				}
				if _, err := os.Lstat(path); goerrors.Is(err, fs.ErrNotExist) {
					continue
				} else if err != nil {
					resultErr = goerrors.Join(resultErr, fmt.Errorf("cannot inspect static SFTP identity file %q of %s %q in auditlog %q: %w", path, kind, target.Name, auditlog.Name, err))
					continue
				}
				keys, err := audit.LoadSftpIdentityPublicKeys([]string{path})
				result = append(result, keys...)
				if err != nil {
					resultErr = goerrors.Join(resultErr, fmt.Errorf("cannot load static SFTP identities of %s %q in auditlog %q: %w", kind, target.Name, auditlog.Name, err))
				}
			}
		}
	}
	if !auditlog.Recording.Enabled {
		loadTargets(auditlog.Recording.Targets.Configured(), "Recording target")
	}
	return result, resultErr
}

func EnsureHostPrivateKeys(conf *configuration.Configuration) ([]crypto.PrivateKey, error) {
	result, _, err := EnsureHostPrivateKeysWithPaths(conf)
	return result, err
}

func EnsureHostPrivateKeysWithPaths(conf *configuration.Configuration) ([]crypto.PrivateKey, []string, error) {
	return configuration.EnsureHostPrivateKeysWithPaths(conf)
}

func (this *Service) logCertificateAuthorities(hostKeys []crypto.PrivateKey) error {
	seen := make(map[string]struct{})
	for i := range this.Configuration.Flows {
		flow := &this.Configuration.Flows[i]
		sshEnvironment, ok := flow.Environment.V.(*configuration.EnvironmentSsh)
		if !ok || sshEnvironment.Certificate == nil {
			continue
		}
		key, path, err := environment.EnsureSshCertificateAuthority(flow)
		if err != nil {
			return err
		}
		if err := environment.ValidateSshCertificateAuthority(key, hostKeys); err != nil {
			return fmt.Errorf("flow %q: %w", flow.Name, err)
		}
		publicKey := key.PublicKey().ToSsh()
		fingerprint := gossh.FingerprintSHA256(publicKey)
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		this.logger().
			With("flow", flow.Name).
			With("path", path).
			With("fingerprint", fingerprint).
			With("publicKey", strings.TrimSpace(string(gossh.MarshalAuthorizedKey(publicKey)))).
			Info("SSH certificate authority available")
	}
	return nil
}

type service struct {
	*Service
	configurationReloader     *configuration.FileReloader
	configurationWatchOptions configuration.FileWatchOptions
	resources                 *runtimeResources
	generationClosed          chan struct{}
	providerCancel            context.CancelFunc
	generationCloseOnce       sync.Once
	generationCloseErr        error
	workCloseOnce             sync.Once
	workCloseErr              error
	closeOnce                 sync.Once
	closeErr                  error
	runtime                   *runtimeGenerations
	generation                *runtimeGeneration
	monitoring                *serviceMonitoring
	web                       *webService
	managementApplication     *clibase.Application[clibase.NoOptions]

	auditIdentities          map[configuration.AuditlogName]*audit.Identity
	auditRecorders           map[configuration.AuditlogName]audit.Recorder
	auditRecorderOrder       []audit.Recorder
	auditDeliveries          map[configuration.AuditlogName]*audit.RemoteDelivery
	auditDeliveryOrder       []*audit.RemoteDelivery
	recordingRepositories    map[configuration.AuditlogName]*sessionRecordingRepository
	recordingRepositoryOrder []configuration.AuditlogName
	recordingTargets         map[configuration.AuditlogName]*audit.RemoteArtifactTargets
	recordingTargetOrder     []configuration.AuditlogName
	recordingDeliveries      map[configuration.AuditlogName]*audit.RemoteArtifactDelivery
	recordingDeliveryOrder   []*audit.RemoteArtifactDelivery
	flowAuditRecorders       map[configuration.FlowName]audit.Recorder
	flowAuditlogs            map[configuration.FlowName]configuration.AuditlogName
	enabledAuditlogs         map[configuration.AuditlogName]bool
	auditlogStates           map[configuration.AuditlogName]*auditlogRuntimeState
	auditOverviewOnce        sync.Once
	auditOverview            *audit.OverviewReader
	managementCursorOnce     sync.Once
	managementCursorKey      [32]byte
	managementCursorErr      error
	unauthenticatedAudit     *unauthenticatedAuditLimiter
	sessions                 session.CloseableRepository
	authorizer               authorization.CloseableAuthorizer
	authorizerDiscovery      authorization.HttpLoginDescriber
	environments             environment.CloseableRepository
	houseKeeper              houseKeeper
	oidcRefresh              oidcRefreshManager
	sessionConnections       sessionConnectionRegistry
	alternatives             alternatives.Provider
	imp                      imp.Imp
	server                   essh.Server
	tunnelServer             essh.Server
	sshTunnel                *sshTunnel
	https                    *https.Endpoint
	tlsManagers              map[string]*transporttls.TLS
	tlsSourceNames           []string
	tlsBindings              map[string]*transporttls.Binding
	tlsChallenges            transporttls.Registry
	tlsChallengeAddresses    bnet.NetAddresses
	httpsForbiddenKeys       []crypto.PublicKey
	auditProtectedKeys       []crypto.PublicKey
	forwardHandler           essh.ForwardedTCPHandler

	knownFlows map[configuration.FlowName]struct{}

	resolvedSshKeysExchanges           []string
	resolvedSshMessagesAuthentications []string
	resolvedSshMessagesCiphers         []string

	activeConnections   atomic.Int64
	connectionLifecycle *connectionLifecycle
	executions          *connectionLifecycle
	terminalAdmissions  *connectionLifecycle
	terminalContext     context.Context
	cancelTerminals     context.CancelFunc
}

type auditlogRuntimeState struct {
	policy          configuration.AuditlogFailurePolicy
	disabled        atomic.Bool
	recordingFailed atomic.Bool
	logOnce         sync.Once
}

func withLazyContextOrFieldExclude[C any](ctx essh.Context, ctxKey any) fields.Lazy {
	return fields.LazyFunc(func() any {
		if v, ok := ctx.Value(ctxKey).(C); ok {
			return v
		}
		return fields.Exclude
	})
}

func (this *service) connection(ctx essh.Context) *connection {
	if v, ok := ctx.Value(connectionCtxKey).(*connection); ok {
		return v
	}
	return nil
}

func (this *service) createNewServerConfig(ctx essh.Context, _ gonet.Conn, target *gossh.ServerConfig) error {
	target.ServerVersion = "SSH-2.0-Engity-Bifroest_" + this.Version.Version()
	target.MaxAuthTries = sshMaxAuthTries(this.Configuration.Ssh.MaxAuthTries)
	target.Config = gossh.Config{
		KeyExchanges: this.resolvedSshKeysExchanges,
		Ciphers:      this.resolvedSshMessagesCiphers,
		MACs:         this.resolvedSshMessagesAuthentications,
	}
	target.VerifiedPublicKeyCallback = this.verifiedPublicKeyAuditCallback(ctx)
	if this.monitoring != nil {
		target.AuthLogCallback = func(_ gossh.ConnMetadata, method string, err error) {
			if method == "none" {
				return
			}
			conn := this.connection(ctx)
			if conn == nil {
				return
			}
			conn.authenticationAttempted.Store(true)
			if err == nil {
				conn.authenticated.Store(true)
			}
			var flow configuration.FlowName
			if auth, _ := ctx.Value(authorizationCtxKey).(authorization.Authorization); auth != nil {
				flow = auth.Flow()
			}
			if method == "publickey" {
				method = "public-key"
			}
			this.monitoring.authenticationAttempt(flow, "ssh", method, monitoringAuthenticationResult(err))
		}
	}
	return nil
}

func sshMaxAuthTries(value uint8) int {
	if value == 0 {
		return -1
	}
	return int(value)
}

func (this *service) Close() (rErr error) {
	return this.close(true)
}

// Failed preparation owns the same resources but must not start remote flushing.
func (this *service) close(flush bool) (rErr error) {
	if this.resources != nil {
		if this.resources.owner != this {
			if !this.runtime.discard(this.generation) {
				return fmt.Errorf("cannot discard an activated runtime generation")
			}
			<-this.generationClosed
			return this.generationCloseErr
		}
		return this.resources.close(flush)
	}
	this.closeOnce.Do(func() { this.closeErr = this.closeUnshared(flush) })
	return this.closeErr
}

// Lean test/adaptor services may own all of their dependencies directly.
func (this *service) closeUnshared(flush bool) (rErr error) {
	if this.runtime != nil {
		this.runtime.stop()
		// Deferred first: workers/providers close before session ownership is
		// forgotten. This never removes persisted sessions.
		defer this.runtime.forgetSessions()
	}
	if this.sshTunnel != nil {
		_ = this.sshTunnel.Close()
	}
	if this.web != nil {
		rErr = goerrors.Join(rErr, this.web.Close())
	}
	if this.terminalAdmissions != nil {
		this.terminalAdmissions.stop()
	}
	if this.cancelTerminals != nil {
		this.cancelTerminals()
	}
	if this.connectionLifecycle != nil {
		this.connectionLifecycle.stop()
	}
	if this.executions != nil {
		this.executions.stop()
	}
	rErr = goerrors.Join(rErr, this.sessionConnections.closeTerminals())
	if this.terminalAdmissions != nil {
		this.terminalAdmissions.waitUntilDrained()
	}
	if this.executions != nil {
		this.executions.waitUntilDrained()
	}
	if this.auditOverview != nil {
		rErr = goerrors.Join(rErr, this.auditOverview.Close())
	}
	if this.managementApplication != nil {
		defer common.KeepCloseError(&rErr, this.managementApplication)
	}
	defer func() { rErr = goerrors.Join(rErr, this.closeAudit(flush)) }()
	defer func() { rErr = goerrors.Join(rErr, this.closeRecording(flush)) }()
	defer common.KeepCloseError(&rErr, this.alternatives)
	defer common.KeepCloseError(&rErr, this.imp)
	defer common.KeepCloseError(&rErr, this.sessions)
	defer common.KeepCloseError(&rErr, this.authorizer)
	defer common.KeepCloseError(&rErr, this.environments)
	defer common.KeepCloseError(&rErr, &this.houseKeeper)
	defer common.KeepCloseError(&rErr, &this.oidcRefresh)
	if this.https != nil {
		defer common.KeepCloseError(&rErr, this.https)
	}
	defer func() { rErr = goerrors.Join(rErr, this.closeTLS()) }()
	return rErr
}

func (this *service) closeSharedResources(flush bool) (rErr error) {
	if this.auditOverview != nil {
		rErr = goerrors.Join(rErr, this.auditOverview.Close())
	}
	common.KeepCloseError(&rErr, this.sessions)
	common.KeepCloseError(&rErr, this.imp)
	common.KeepCloseError(&rErr, this.alternatives)
	rErr = goerrors.Join(rErr, this.closeRecording(flush), this.closeAudit(flush))
	return rErr
}

func (this *service) closeRecording(flush bool) (result error) {
	if flush && len(this.recordingDeliveryOrder) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), remoteAuditDeliveryShutdownTimeout)
		var wait sync.WaitGroup
		for _, delivery := range this.recordingDeliveryOrder {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if err := delivery.Flush(ctx); err != nil {
					this.logger().WithError(err).Warn("cannot flush remote Recording delivery while shutting down; artifacts remain local")
				}
			}()
		}
		wait.Wait()
		cancel()
	}
	for _, delivery := range this.recordingDeliveryOrder {
		result = goerrors.Join(result, delivery.Close())
	}
	for index := len(this.recordingTargetOrder) - 1; index >= 0; index-- {
		name := this.recordingTargetOrder[index]
		if this.recordingDeliveries[name] != nil {
			continue
		}
		if err := this.recordingTargets[name].Close(); err != nil {
			result = goerrors.Join(result, fmt.Errorf("cannot close Recording targets of auditlog %q: %w", name, err))
		}
	}
	for _, name := range this.recordingRepositoryOrder {
		repository := this.recordingRepositories[name]
		var err error
		state := this.auditlogStates[name]
		if state != nil && state.recordingFailed.Load() {
			err = repository.CloseAfterAcceptedFailure()
		} else {
			err = repository.Close()
		}
		if err != nil {
			result = goerrors.Join(result, fmt.Errorf("cannot close Recording repository of auditlog %q: %w", name, err))
		}
	}
	return result
}

func (this *service) closeAudit(flush bool) (result error) {
	if flush {
		if this.unauthenticatedAudit != nil {
			if err := this.unauthenticatedAudit.Flush(context.Background()); err != nil {
				result = goerrors.Join(result, errors.System.Newf("cannot flush unauthenticated audit aggregates: %w", err))
			}
		}
		for _, recorder := range this.auditRecorderOrder {
			if sealable, ok := recorder.(audit.SealableRecorder); ok {
				result = goerrors.Join(result, sealable.Seal())
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), remoteAuditDeliveryShutdownTimeout)
		var wait sync.WaitGroup
		for _, delivery := range this.auditDeliveryOrder {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if err := delivery.Flush(ctx); err != nil {
					this.logger().WithError(err).Warn("cannot flush remote audit delivery while shutting down; segments remain local")
				}
			}()
		}
		wait.Wait()
		cancel()
	}
	for _, delivery := range this.auditDeliveryOrder {
		result = goerrors.Join(result, delivery.Close())
	}
	return goerrors.Join(result, this.closeAuditRecorders())
}

func (this *service) closeAuditRecorders() (result error) {
	for _, recorder := range this.auditRecorderOrder {
		result = goerrors.Join(result, recorder.Close())
	}
	return result
}

func validateAuditlogRuntimePaths(auditlogs configuration.Auditlogs) error {
	type resolvedAuditlog struct {
		name         configuration.AuditlogName
		identityFile string
		journal      string
	}
	var resolved []resolvedAuditlog
	for index := range auditlogs {
		configured := &auditlogs[index]
		identityFile, err := sys.CanonicalPath(configured.IdentityFile)
		if err != nil {
			return errors.Config.Newf("cannot resolve identity file of auditlog %q: %w", configured.Name, err)
		}
		journal, err := sys.CanonicalPath(configured.Directory)
		if err != nil {
			return errors.Config.Newf("cannot resolve journal directory of auditlog %q: %w", configured.Name, err)
		}
		configured.Directory = journal
		configured.IdentityFile = identityFile
		if configured.Recording.Enabled {
			recording, err := sys.CanonicalPath(configured.Recording.Directory)
			if err != nil {
				return errors.Config.Newf("cannot resolve recording directory of auditlog %q: %w", configured.Name, err)
			}
			configured.Recording.Directory = recording
		}
		resolved = append(resolved, resolvedAuditlog{configured.Name, identityFile, journal})
	}
	for leftIndex, left := range resolved {
		for rightIndex := leftIndex + 1; rightIndex < len(resolved); rightIndex++ {
			right := resolved[rightIndex]
			if left.journal != "" && right.journal != "" && (runtimePathContains(left.journal, right.journal) || runtimePathContains(right.journal, left.journal)) {
				return errors.Config.Newf("auditlog %q journal overlaps auditlog %q journal", left.name, right.name)
			}
			// Equal key paths are allowed, but strictly nested paths are not.
			if runtimePathContains(left.identityFile, right.identityFile) != runtimePathContains(right.identityFile, left.identityFile) {
				return errors.Config.Newf("auditlog %q identity file overlaps auditlog %q identity file", left.name, right.name)
			}
		}
		for _, other := range resolved {
			if other.journal != "" && (runtimePathContains(left.identityFile, other.journal) || runtimePathContains(other.journal, left.identityFile)) {
				return errors.Config.Newf("auditlog %q identity file overlaps auditlog %q journal", left.name, other.name)
			}
		}
	}
	return nil
}

func validateRecordingRuntimePathOverlaps(conf *configuration.Configuration, storage string) error {
	for recordingIndex, recordingAuditlog := range conf.Auditlogs {
		if !recordingAuditlog.Recording.Enabled {
			continue
		}
		recordingDirectory := recordingAuditlog.Recording.Directory
		if storage != "" && runtimePathsOverlap(recordingDirectory, storage) {
			return errors.Config.Newf("auditlog %q recording directory overlaps session storage", recordingAuditlog.Name)
		}
		for auditlogIndex, auditlog := range conf.Auditlogs {
			if runtimePathsOverlap(recordingDirectory, auditlog.Directory) {
				return errors.Config.Newf("auditlog %q recording directory overlaps auditlog %q journal", recordingAuditlog.Name, auditlog.Name)
			}
			if runtimePathsOverlap(recordingDirectory, auditlog.IdentityFile) {
				return errors.Config.Newf("auditlog %q recording directory overlaps auditlog %q identity file", recordingAuditlog.Name, auditlog.Name)
			}
			if recordingIndex < auditlogIndex && auditlog.Recording.Enabled && runtimePathsOverlap(recordingDirectory, auditlog.Recording.Directory) {
				return errors.Config.Newf("auditlog %q recording directory overlaps auditlog %q recording directory", recordingAuditlog.Name, auditlog.Name)
			}
			if !auditlog.EncryptionPublicKeyFile.IsZero() && runtimePathsOverlap(recordingDirectory, string(auditlog.EncryptionPublicKeyFile)) {
				return errors.Config.Newf("auditlog %q recording directory overlaps auditlog %q encryption public key file", recordingAuditlog.Name, auditlog.Name)
			}
			for _, target := range auditlog.Targets {
				sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
				if !ok || sftp == nil {
					continue
				}
				if !sftp.KnownHostsFile.IsZero() && runtimePathsOverlap(recordingDirectory, string(sftp.KnownHostsFile)) {
					return errors.Config.Newf("auditlog %q recording directory overlaps auditlog %q SFTP target %q known hosts file", recordingAuditlog.Name, auditlog.Name, target.Name)
				}
				for index, identityFile := range sftp.IdentityFiles {
					if runtimePathsOverlap(recordingDirectory, identityFile) {
						return errors.Config.Newf("auditlog %q recording directory overlaps auditlog %q SFTP target %q identity file [%d]", recordingAuditlog.Name, auditlog.Name, target.Name, index)
					}
				}
			}
			if !auditlog.Recording.Enabled {
				continue
			}
			for _, target := range auditlog.Recording.Targets.Configured() {
				sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
				if !ok || sftp == nil {
					continue
				}
				if !sftp.KnownHostsFile.IsZero() && runtimePathsOverlap(recordingDirectory, string(sftp.KnownHostsFile)) {
					return errors.Config.Newf("auditlog %q recording directory overlaps auditlog %q Recording SFTP target %q known hosts file", recordingAuditlog.Name, auditlog.Name, target.Name)
				}
				for index, identityFile := range sftp.IdentityFiles {
					if runtimePathsOverlap(recordingDirectory, identityFile) {
						return errors.Config.Newf("auditlog %q recording directory overlaps auditlog %q Recording SFTP target %q identity file [%d]", recordingAuditlog.Name, auditlog.Name, target.Name, index)
					}
				}
			}
		}
	}
	return nil
}

func validateRuntimePaths(conf *configuration.Configuration) error {
	candidate := cloneRuntimePathConfiguration(conf)
	if err := validateRuntimePathCandidate(&candidate); err != nil {
		return err
	}
	*conf = candidate
	return nil
}

func cloneRuntimePathConfiguration(conf *configuration.Configuration) configuration.Configuration {
	result := *conf
	if conf.Http != nil {
		cloned := *conf.Http
		if conf.Http.Tls != nil {
			tls := *conf.Http.Tls
			tls.Certificates = slices.Clone(conf.Http.Tls.Certificates)
			if tls.Acme != nil {
				automation := *tls.Acme
				tls.Acme = &automation
			}
			cloned.Tls = &tls
		}
		cloned.Upstream.TrustedPeers = slices.Clone(conf.Http.Upstream.TrustedPeers)
		cloned.CustomCss = slices.Clone(conf.Http.CustomCss)
		cloned.CustomJs = slices.Clone(conf.Http.CustomJs)
		result.Http = &cloned
	}
	if conf.Monitoring != nil {
		cloned := *conf.Monitoring
		if conf.Monitoring.Tls != nil {
			tls := *conf.Monitoring.Tls
			tls.Certificates = slices.Clone(tls.Certificates)
			if tls.Acme != nil {
				automation := *tls.Acme
				tls.Acme = &automation
			}
			cloned.Tls = &tls
		}
		result.Monitoring = &cloned
	}
	result.Auditlogs = slices.Clone(conf.Auditlogs)
	for auditlogIndex := range result.Auditlogs {
		result.Auditlogs[auditlogIndex].Targets = slices.Clone(conf.Auditlogs[auditlogIndex].Targets)
		for targetIndex := range result.Auditlogs[auditlogIndex].Targets {
			sftp, ok := conf.Auditlogs[auditlogIndex].Targets[targetIndex].V.(*configuration.AuditlogTargetSftp)
			if !ok || sftp == nil {
				continue
			}
			cloned := *sftp
			cloned.IdentityFiles = slices.Clone(sftp.IdentityFiles)
			result.Auditlogs[auditlogIndex].Targets[targetIndex].V = &cloned
		}
		configured := &conf.Auditlogs[auditlogIndex]
		if !configured.Recording.Enabled {
			continue
		}
		configuredTargets := configured.Recording.Targets.Configured()
		if len(configuredTargets) == 0 {
			continue
		}
		resultTargets := &result.Auditlogs[auditlogIndex].Recording.Targets
		resultTargets.Targets = slices.Clone(configuredTargets)
		for targetIndex := range resultTargets.Targets {
			sftp, ok := configuredTargets[targetIndex].V.(*configuration.AuditlogTargetSftp)
			if !ok || sftp == nil {
				continue
			}
			cloned := *sftp
			cloned.IdentityFiles = slices.Clone(sftp.IdentityFiles)
			resultTargets.Targets[targetIndex].V = &cloned
		}
	}
	if sessionFs, ok := conf.Session.V.(*configuration.SessionFs); ok && sessionFs != nil {
		cloned := *sessionFs
		result.Session.V = &cloned
	}
	return result
}

func validateRuntimePathCandidate(conf *configuration.Configuration) error {
	if err := validateAuditlogRuntimePaths(conf.Auditlogs); err != nil {
		return err
	}
	var storage string
	sessionFs, ok := conf.Session.V.(*configuration.SessionFs)
	if ok {
		resolved, err := sys.CanonicalPath(sessionFs.Storage)
		if err != nil {
			return errors.Config.Newf("cannot resolve session storage: %w", err)
		}
		sessionFs.Storage = resolved
		storage = resolved
	}
	for auditlogIndex := range conf.Auditlogs {
		auditlog := &conf.Auditlogs[auditlogIndex]
		if storage != "" {
			if err := validateSessionStorageRuntimePath(storage, auditlog.IdentityFile, fmt.Sprintf("auditlog %q identity file", auditlog.Name)); err != nil {
				return err
			}
			if err := validateSessionStorageRuntimePath(storage, auditlog.Directory, fmt.Sprintf("auditlog %q journal", auditlog.Name)); err != nil {
				return err
			}
		}
		if !auditlog.EncryptionPublicKeyFile.IsZero() {
			resolved, err := canonicalRuntimePathOutsideSessionStorage(storage, string(auditlog.EncryptionPublicKeyFile), fmt.Sprintf("auditlog %q encryption public key file", auditlog.Name))
			if err != nil {
				return err
			}
			auditlog.EncryptionPublicKeyFile = crypto.PublicKeysFile(resolved)
		}
		for targetIndex := range auditlog.Targets {
			target := &auditlog.Targets[targetIndex]
			sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
			if !ok || sftp == nil {
				continue
			}
			if !sftp.KnownHostsFile.IsZero() {
				resolved, err := canonicalRuntimePathOutsideSessionStorage(storage, string(sftp.KnownHostsFile), fmt.Sprintf("auditlog %q SFTP target %q known hosts file", auditlog.Name, target.Name))
				if err != nil {
					return err
				}
				sftp.KnownHostsFile = crypto.KnownHostsFile(resolved)
			}
			for index, identityFile := range sftp.IdentityFiles {
				resolved, err := canonicalRuntimePathOutsideSessionStorage(storage, identityFile, fmt.Sprintf("auditlog %q SFTP target %q identity file [%d]", auditlog.Name, target.Name, index))
				if err != nil {
					return err
				}
				sftp.IdentityFiles[index] = resolved
			}
		}
		configuredRecordingTargets := auditlog.Recording.Targets.Configured()
		for targetIndex := range configuredRecordingTargets {
			target := &configuredRecordingTargets[targetIndex]
			sftp, ok := target.V.(*configuration.AuditlogTargetSftp)
			if !auditlog.Recording.Enabled || !ok || sftp == nil {
				continue
			}
			if !sftp.KnownHostsFile.IsZero() {
				resolved, err := canonicalRuntimePathOutsideSessionStorage(storage, string(sftp.KnownHostsFile), fmt.Sprintf("auditlog %q Recording SFTP target %q known hosts file", auditlog.Name, target.Name))
				if err != nil {
					return err
				}
				sftp.KnownHostsFile = crypto.KnownHostsFile(resolved)
			}
			for index, identityFile := range sftp.IdentityFiles {
				resolved, err := canonicalRuntimePathOutsideSessionStorage(storage, identityFile, fmt.Sprintf("auditlog %q Recording SFTP target %q identity file [%d]", auditlog.Name, target.Name, index))
				if err != nil {
					return err
				}
				sftp.IdentityFiles[index] = resolved
			}
		}
	}
	if err := validateRecordingRuntimePathOverlaps(conf, storage); err != nil {
		return err
	}
	if err := validateStaticKeyRuntimePaths(conf, storage); err != nil {
		return err
	}
	return validateHTTPRuntimePaths(conf, storage)
}

func validateStaticKeyRuntimePaths(conf *configuration.Configuration, storage string) error {
	check := func(path, description string) error {
		resolved, err := sys.CanonicalPath(path)
		if err != nil {
			return errors.Config.Newf("cannot resolve %s: %w", description, err)
		}
		if storage != "" && runtimePathsOverlap(resolved, storage) {
			return errors.Config.Newf("%s overlaps session storage", description)
		}
		for _, auditlog := range conf.Auditlogs {
			if runtimePathsOverlap(resolved, auditlog.IdentityFile) {
				return errors.Config.Newf("%s overlaps auditlog %q identity file", description, auditlog.Name)
			}
			if runtimePathsOverlap(resolved, auditlog.Directory) {
				return errors.Config.Newf("%s overlaps auditlog %q journal", description, auditlog.Name)
			}
			if auditlog.Recording.Enabled && runtimePathsOverlap(resolved, auditlog.Recording.Directory) {
				return errors.Config.Newf("%s overlaps auditlog %q recording directory", description, auditlog.Name)
			}
		}
		return nil
	}
	hostKeys, err := conf.Ssh.Keys.HostKeys.Render(noopContext{})
	if err != nil {
		return errors.Config.Newf("cannot render hostKeys: %w", err)
	}
	for _, path := range hostKeys {
		if path != "" {
			if err := check(path, "SSH host key"); err != nil {
				return err
			}
		}
	}
	for _, flow := range conf.Flows {
		sshEnvironment, ok := flow.Environment.V.(*configuration.EnvironmentSsh)
		if !ok || sshEnvironment == nil {
			continue
		}
		if certificate := sshEnvironment.Certificate; certificate != nil {
			for _, path := range []struct {
				value       string
				description string
			}{
				{certificate.IdentityFile.String(), fmt.Sprintf("flow %q SSH certificate identity file", flow.Name)},
				{certificate.AuthorityIdentityFile.String(), fmt.Sprintf("flow %q SSH certificate authority file", flow.Name)},
			} {
				if err := check(strings.TrimSpace(path.value), path.description); err != nil {
					return err
				}
			}
			continue
		}
		for _, path := range sshEnvironment.IdentityFiles {
			if path.IsHardCoded() {
				if err := check(strings.TrimSpace(path.String()), fmt.Sprintf("flow %q static SSH identity file", flow.Name)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func canonicalRuntimePathOutsideSessionStorage(storage, candidate, description string) (string, error) {
	resolved, err := sys.CanonicalPath(candidate)
	if err != nil {
		return "", errors.Config.Newf("cannot resolve %s: %w", description, err)
	}
	if storage != "" && (runtimePathContains(storage, resolved) || runtimePathContains(resolved, storage)) {
		return "", errors.Config.Newf("session storage overlaps %s", description)
	}
	return resolved, nil
}

func validateSessionStorageRuntimePath(storage, candidate, description string) error {
	_, err := canonicalRuntimePathOutsideSessionStorage(storage, candidate, description)
	return err
}

func runtimePathContains(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func runtimePathsOverlap(left, right string) bool {
	return runtimePathContains(left, right) || runtimePathContains(right, left)
}
