package service

import (
	"context"
	goerrors "errors"
	"fmt"
	gonet "net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
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

	Logger log.Logger
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

	if msg, err := this.Configuration.StartMessage.Render(noopContext{}); err != nil {
		return err
	} else if msg != "" {
		for _, line := range strings.Split(msg, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				log.Warn(line)
			}
		}
	}

	svc, err := this.prepare()
	if err != nil {
		return err
	}
	closeService := true
	defer func() {
		if closeService {
			common.KeepCloseError(&rErr, svc)
		}
	}()

	lns := make([]struct {
		ln   gonet.Listener
		addr bnet.Address
	}, len(this.Configuration.Ssh.Addresses))
	closeLns := func() {
		for _, ln := range lns {
			if ln.ln != nil {
				if err := ln.ln.Close(); this.isProblematicError(err) && rErr == nil {
					rErr = err
				}
			}
		}
	}
	defer closeLns()

	for i, addr := range this.Configuration.Ssh.Addresses {
		ln, err := addr.Listen()
		if err != nil {
			return fmt.Errorf("cannot listen to %v: %w", addr, err)
		}
		lns[i].addr = addr
		lns[i].ln = ln
	}

	this.logger().WithAll(sys.VersionToMap(this.Version)).Info("started")

	serveCtx, cancelServe := context.WithCancelCause(ctx)
	defer cancelServe(nil)
	gracefulShutdownTimeout := this.Configuration.Ssh.GracefulShutdownTimeout.Native()
	var beginShutdownOnce sync.Once
	var shutdownStartedAt time.Time
	beginShutdown := func() {
		beginShutdownOnce.Do(func() {
			shutdownStartedAt = time.Now()
			svc.connectionLifecycle.stop()
		})
	}
	stopLifecycleWatch := context.AfterFunc(serveCtx, beginShutdown)
	defer stopLifecycleWatch()
	type serveResult struct {
		address bnet.Address
		err     error
	}
	done := make(chan serveResult, len(lns))
	for _, ln := range lns {
		go func() {
			l := this.logger().With("address", ln.ln.Addr())
			l.Info("listening...")
			err := svc.server.Serve(serveCtx, ln.ln)
			if this.isProblematicError(err) {
				l.WithError(err).Error("listening... FAILED!")
			} else {
				l.Info("listening... DONE!")
			}
			done <- serveResult{ln.addr, err}
		}()
	}

	forcedShutdown := false
	for i := 0; i < len(lns); i++ {
		result := <-done
		if i == 0 {
			beginShutdown()
			cancelServe(result.err)
		}
		forcedShutdown = forcedShutdown || goerrors.Is(result.err, essh.ErrGracefulShutdownTimeout)
		if this.isProblematicError(result.err) {
			rErr = goerrors.Join(rErr, fmt.Errorf("SSH listener %v failed: %w", result.address, result.err))
		}
	}
	handlerDrainTimeout := remainingGracefulShutdownTimeout(gracefulShutdownTimeout, shutdownStartedAt, time.Now())
	if forcedShutdown {
		handlerDrainTimeout = 0
	}
	if !svc.connectionLifecycle.wait(handlerDrainTimeout) {
		drainErr := fmt.Errorf("SSH connection handlers did not finish within the graceful shutdown timeout of %s", gracefulShutdownTimeout)
		this.logger().WithError(drainErr).Warn("delaying service cleanup until SSH connection handlers finish")
		if this.isProblematicError(context.Cause(serveCtx)) {
			rErr = goerrors.Join(rErr, drainErr)
		}
		closeService = false
		go func() {
			svc.connectionLifecycle.waitUntilDrained()
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
	fail := func(err error) (*service, error) {
		return nil, fmt.Errorf("cannot prepare service: %w", err)
	}
	if err := this.Configuration.Validate(); err != nil {
		return fail(err)
	}
	if err := validateRuntimePaths(&this.Configuration); err != nil {
		return fail(err)
	}

	ctx := context.Background()
	svc = &service{
		Service:             this,
		connectionLifecycle: newConnectionLifecycle(),
	}

	svc.knownFlows = make(map[configuration.FlowName]struct{})
	for _, flow := range this.Configuration.Flows {
		svc.knownFlows[flow.Name] = struct{}{}
	}

	sshKeysExchanges, err := this.Configuration.Ssh.Keys.Exchanges.MarshalTexts()
	if err != nil {
		return fail(err)
	}
	svc.resolvedSshKeysExchanges = make([]string, len(sshKeysExchanges))
	for i, n := range sshKeysExchanges {
		svc.resolvedSshKeysExchanges[i] = string(n)
	}
	sshMessagesAuthentications, err := this.Configuration.Ssh.Messages.Authentications.MarshalTexts()
	if err != nil {
		return fail(err)
	}
	svc.resolvedSshMessagesAuthentications = make([]string, len(sshMessagesAuthentications))
	for i, n := range sshMessagesAuthentications {
		svc.resolvedSshMessagesAuthentications[i] = string(n)
	}
	sshMessagesCiphers, err := this.Configuration.Ssh.Messages.Ciphers.MarshalTexts()
	if err != nil {
		return fail(err)
	}
	svc.resolvedSshMessagesCiphers = make([]string, len(sshMessagesCiphers))
	for i, n := range sshMessagesCiphers {
		svc.resolvedSshMessagesCiphers[i] = string(n)
	}

	hostSigners, err := this.loadHostPrivateKeys()
	if err != nil {
		return fail(err)
	}
	resourcesOwnedByService := false
	defer func(preparedService *service) {
		if !resourcesOwnedByService {
			recordingErr := preparedService.closeRecording(false)
			auditErr := preparedService.closeAudit(false)
			err = goerrors.Join(err, recordingErr, auditErr)
		}
	}(svc)
	if err := this.prepareAudit(ctx, svc, hostSigners); err != nil {
		return fail(err)
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
	if svc.sessions, err = session.NewFacadeRepository(ctx, &this.Configuration.Session); err != nil {
		return fail(err)
	}
	sessionRepositoryPrepared := false
	defer func(preparedService *service) {
		if !sessionRepositoryPrepared {
			_ = preparedService.sessions.Close()
		}
	}(svc)
	if svc.authorizer, err = authorization.NewAuthorizerFacadeWithObserver(ctx, &this.Configuration.Flows, svc.observeFlowAuthorization); err != nil {
		return fail(err)
	}
	if svc.environments, err = environment.NewRepositoryFacadeWithHostKeys(ctx, &this.Configuration.Flows, svc.alternatives, svc.imp, hostSigners); err != nil {
		return fail(err)
	}
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

	sessionRepositoryPrepared = true
	resourcesOwnedByService = true
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
		svc.enabledAuditlogs[auditlog.Name] = auditlog.Enabled
		svc.auditlogStates[auditlog.Name] = &auditlogRuntimeState{policy: auditlog.FailurePolicy}
	}

	serverPrivateKeys := hostSigners
	sftpIdentityPublicKeysByAuditlog := make(map[configuration.AuditlogName][]crypto.PublicKey, len(this.Configuration.Auditlogs))
	var failedSftpIdentityPublicKeys []crypto.PublicKey
	if hasEncryptedAuditlog(this.Configuration.Auditlogs) {
		serverPrivateKeys, err = loadStaticPrivateKeysForAuditEncryption(this.Configuration.Flows, hostSigners)
		if err != nil {
			return err
		}
		for index := range this.Configuration.Auditlogs {
			auditlog := &this.Configuration.Auditlogs[index]
			if !auditlog.Enabled {
				continue
			}
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
	}
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		if svc.auditlogDisabled(auditlog.Name) {
			continue
		}
		identity, identityErr := audit.EnsureIdentity(auditlog)
		if identityErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "identity", identityErr); err != nil {
				return err
			}
			continue
		}
		if identityErr := identity.ValidateDedicatedFrom(hostSigners); identityErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "identity", identityErr); err != nil {
				return err
			}
			continue
		}
		if identityErr := validateDistinctAuditIdentity(svc.auditIdentities, auditlog.Name, identity); identityErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "identity", identityErr); err != nil {
				return err
			}
			continue
		}
		svc.auditIdentities[auditlog.Name] = identity
	}
	auditIdentities := make([]*audit.Identity, 0, len(svc.auditIdentities))
	for _, identity := range svc.auditIdentities {
		auditIdentities = append(auditIdentities, identity)
	}
	sftpIdentityPublicKeys := failedSftpIdentityPublicKeys
	for auditlog, keys := range sftpIdentityPublicKeysByAuditlog {
		if !svc.auditlogDisabled(auditlog) {
			sftpIdentityPublicKeys = append(sftpIdentityPublicKeys, keys...)
		}
	}
	resolvedEncryptionPublicKeys := make(map[configuration.AuditlogName]crypto.PublicKeys, len(this.Configuration.Auditlogs))
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		if !auditlog.Enabled || svc.auditlogDisabled(auditlog.Name) {
			continue
		}
		encryptionPublicKey, encryptionErr := audit.ResolveEncryptionPublicKey(auditlog.EncryptionPublicKey, auditlog.EncryptionPublicKeyFile)
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
		if encryptionErr := audit.ValidateEncryptionRecipientDedicatedFromAuditIdentities(encryptionPublicKey, auditIdentities); encryptionErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "encryption", encryptionErr); err != nil {
				return err
			}
			continue
		}
		resolvedEncryptionPublicKeys[auditlog.Name] = encryptionPublicKey
	}
	for index := range this.Configuration.Auditlogs {
		auditlog := &this.Configuration.Auditlogs[index]
		if !auditlog.Enabled || !auditlog.Recording.Enabled || svc.auditlogDisabled(auditlog.Name) {
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
		repository, repositoryErr := newSessionRecordingRepository(ctx, auditlog.Recording, svc.auditIdentities[auditlog.Name], resolvedEncryptionPublicKeys[auditlog.Name], auditlog.Name, targets)
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
		if auditlog.Enabled {
			recorderConfiguration.EncryptionPublicKey = resolvedEncryptionPublicKeys[auditlog.Name]
			recorderConfiguration.EncryptionPublicKeyFile = ""
		}
		recorder, recorderErr := audit.NewRecorder(&recorderConfiguration, identity)
		if recorderErr != nil {
			if err := svc.handleAuditlogFailure(auditlog.Name, "journal", recorderErr); err != nil {
				return err
			}
			svc.auditRecorders[auditlog.Name] = audit.NewNoopRecorder()
			continue
		}
		policyRecorder := audit.Recorder(recorder)
		if auditlog.FailurePolicy == configuration.AuditlogFailurePolicyBestEffort {
			policyRecorder = &failurePolicyAuditRecorder{service: svc, auditlog: auditlog.Name, delegate: recorder}
		}
		if auditlog.Enabled && len(auditlog.Targets) > 0 {
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
	for _, flow := range this.Configuration.Flows {
		svc.flowAuditRecorders[flow.Name] = svc.auditRecorders[flow.Auditlog]
		svc.flowAuditlogs[flow.Name] = flow.Auditlog
	}
	svc.unauthenticatedAudit = newUnauthenticatedAuditLimiter(this.Configuration.Ssh.UnauthenticatedAudit)
	return nil
}

func (this *Service) prepareServer(_ context.Context, svc *service, hostPrivateKeys []crypto.PrivateKey) (err error) {
	sshConfig := &svc.Configuration.Ssh

	svc.server.Logger = svc.Service.logger()
	svc.server.RequireHostSigners = true
	svc.server.RequireClientAuth = true
	svc.server.HandshakeTimeout = new(sshConfig.HandshakeTimeout.Native())
	svc.server.IdleTimeout = new(time.Duration(0)) // handled by service's connection
	svc.server.MaxTimeout = new(time.Duration(0))  // handled by service's connection
	svc.server.SessionRequestTimeout = new(sshConfig.SessionRequestTimeout.Native())
	svc.server.MaxStartups = &essh.MaxStartupsConfig{
		Start: int(sshConfig.MaxStartupsStart),
		Rate:  int(sshConfig.MaxStartupsRate),
		Full:  int(sshConfig.MaxStartupsFull),
	}
	svc.server.MaxSessionsPerConnection = new(int(sshConfig.MaxSessionsPerConnection))
	svc.server.MaxChannelsPerConnection = new(int(sshConfig.MaxChannelsPerConnection))
	svc.server.MaxReverseForwardsPerConnection = new(int(sshConfig.MaxReverseForwardsPerConnection))
	svc.server.MaxConnections = new(0)
	svc.server.MaxChannels = new(int(sshConfig.MaxChannels))
	svc.server.MaxReverseForwards = new(int(sshConfig.MaxReverseForwards))
	svc.server.GracefulShutdownHandler = essh.NewGracefulShutdownTimeoutHandler(sshConfig.GracefulShutdownTimeout.Native())
	if sshConfig.ProxyProtocol {
		svc.server.ProxyProtocol = new(essh.ProxyProtocolConfig)
	}
	svc.server.ServerConfigCallback = svc.createNewServerConfig
	svc.server.ConnCallback = svc.onNewConnConnection
	svc.server.ConnectionFailedCallback = svc.onConnectionFailed
	svc.server.DisconnectCallback = svc.onDisconnected
	svc.server.Handler = svc.handleSshShellSession
	svc.server.PtyCallback = svc.onPtyRequest
	svc.server.SessionRequestCallback = svc.onSessionRequest
	svc.server.ReversePortForwardingCallback = svc.onReversePortForwardingRequested
	svc.server.PublicKeyHandler = svc.handlePublicKey
	svc.server.PasswordHandler = svc.handlePassword
	svc.server.KeyboardInteractiveHandler = svc.handleKeyboardInteractiveChallenge
	svc.server.BannerHandler = svc.handleBanner
	svc.server.AgentForwardingCallback = svc.onAgentForwardingRequested
	svc.server.RequestHandlers = map[string]essh.RequestHandler{
		"tcpip-forward":        svc.forwardHandler.HandleSSHRequest,
		"cancel-tcpip-forward": svc.forwardHandler.HandleSSHRequest,
	}
	svc.server.ChannelHandlers = map[string]essh.ChannelHandler{
		"session":      svc.handleNewSshSession,
		"direct-tcpip": svc.handleNewDirectTcpIp,
	}
	svc.server.SubsystemHandlers = map[string]essh.SubsystemHandler{
		"sftp": svc.handleSshSftpSession,
	}
	svc.server.HostSigners = make([]essh.Signer, len(hostPrivateKeys))
	for i, v := range hostPrivateKeys {
		svc.server.HostSigners[i] = v.ToSsh()
	}

	return nil
}

func (this *Service) loadHostPrivateKeys() ([]crypto.PrivateKey, error) {
	return EnsureHostPrivateKeys(&this.Configuration)
}

func hasEncryptedAuditlog(auditlogs configuration.Auditlogs) bool {
	for _, auditlog := range auditlogs {
		if auditlog.Enabled && (!auditlog.EncryptionPublicKey.IsZero() || !auditlog.EncryptionPublicKeyFile.IsZero()) {
			return true
		}
	}
	return false
}

func loadStaticPrivateKeysForAuditEncryption(flows configuration.Flows, hostKeys []crypto.PrivateKey) ([]crypto.PrivateKey, error) {
	result := append([]crypto.PrivateKey(nil), hostKeys...)
	for index := range flows {
		flow := &flows[index]
		sshEnvironment, ok := flow.Environment.V.(*configuration.EnvironmentSsh)
		if !ok {
			continue
		}
		if sshEnvironment.Certificate != nil {
			identity, _, err := environment.EnsureSshCertificateIdentity(flow)
			if err != nil {
				return nil, err
			}
			authority, _, err := environment.EnsureSshCertificateAuthority(flow)
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
			key, err := crypto.EnsureKeyFile(path, nil, nil)
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

func EnsureHostPrivateKeys(conf *configuration.Configuration) ([]crypto.PrivateKey, error) {
	result, _, err := EnsureHostPrivateKeysWithPaths(conf)
	return result, err
}

func EnsureHostPrivateKeysWithPaths(conf *configuration.Configuration) ([]crypto.PrivateKey, []string, error) {
	if conf == nil {
		return nil, nil, fmt.Errorf("nil configuration")
	}
	kc := &conf.Ssh.Keys

	hostKeys, err := kc.HostKeys.Render(noopContext{})
	if err != nil {
		return nil, nil, errors.Config.Newf("cannot render hostKeys: %w", err)
	}

	var result []crypto.PrivateKey
	var resultPaths []string
	for _, fn := range hostKeys {
		if fn == "" {
			continue
		}
		pk, err := crypto.EnsureKeyFile(fn, &crypto.KeyRequirement{
			Type: crypto.KeyTypeEd25519,
		}, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot ensure host key: %w", err)
		}

		if ok, err := kc.KeyAllowed(pk); err != nil {
			return nil, nil, fmt.Errorf("cannot check if host key %q is allowed or not: %w", fn, err)
		} else if !ok {
			return nil, nil, fmt.Errorf("cannot check if host key %q is not allowed by restrictions: %w", fn, err)
		}
		result = append(result, pk)
		resultPaths = append(resultPaths, fn)
	}
	return result, resultPaths, nil
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
	unauthenticatedAudit     *unauthenticatedAuditLimiter
	sessions                 session.CloseableRepository
	authorizer               authorization.CloseableAuthorizer
	environments             environment.CloseableRepository
	houseKeeper              houseKeeper
	alternatives             alternatives.Provider
	imp                      imp.Imp
	server                   essh.Server
	forwardHandler           essh.ForwardedTCPHandler

	knownFlows map[configuration.FlowName]struct{}

	resolvedSshKeysExchanges           []string
	resolvedSshMessagesAuthentications []string
	resolvedSshMessagesCiphers         []string

	activeConnections   atomic.Int64
	connectionLifecycle *connectionLifecycle
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
	release, ok := this.connectionLifecycle.register()
	if !ok {
		return context.Canceled
	}
	ctx.SetValue(connectionLifecycleCtxKey, release)

	target.ServerVersion = "SSH-2.0-Engity-Bifroest_" + this.Version.Version()
	target.MaxAuthTries = sshMaxAuthTries(this.Configuration.Ssh.MaxAuthTries)
	target.Config = gossh.Config{
		KeyExchanges: this.resolvedSshKeysExchanges,
		Ciphers:      this.resolvedSshMessagesCiphers,
		MACs:         this.resolvedSshMessagesAuthentications,
	}
	target.VerifiedPublicKeyCallback = this.verifiedPublicKeyAuditCallback(ctx)
	return nil
}

func sshMaxAuthTries(value uint8) int {
	if value == 0 {
		return -1
	}
	return int(value)
}

func (this *service) Close() (rErr error) {
	defer func() { rErr = goerrors.Join(rErr, this.closeAudit(true)) }()
	defer func() { rErr = goerrors.Join(rErr, this.closeRecording(true)) }()
	defer common.KeepCloseError(&rErr, this.alternatives)
	defer common.KeepCloseError(&rErr, this.imp)
	defer common.KeepCloseError(&rErr, this.sessions)
	defer common.KeepCloseError(&rErr, this.authorizer)
	defer common.KeepCloseError(&rErr, this.environments)
	defer common.KeepCloseError(&rErr, &this.houseKeeper)
	return nil
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

func validateDistinctAuditIdentity(existing map[configuration.AuditlogName]*audit.Identity, name configuration.AuditlogName, candidate *audit.Identity) error {
	if candidate == nil {
		return nil
	}
	for existingName, identity := range existing {
		if identity != nil && identity.ProducerId() == candidate.ProducerId() {
			return errors.Config.Newf("auditlogs %q and %q use the same signing identity", existingName, name)
		}
	}
	return nil
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
		if !configured.Enabled {
			continue
		}
		identityFile, err := sys.CanonicalPath(configured.IdentityFile)
		if err != nil {
			return errors.Config.Newf("cannot resolve identity file of auditlog %q: %w", configured.Name, err)
		}
		journal, err := sys.CanonicalPath(configured.Journal.Directory)
		if err != nil {
			return errors.Config.Newf("cannot resolve journal directory of auditlog %q: %w", configured.Name, err)
		}
		configured.IdentityFile = identityFile
		configured.Journal.Directory = journal
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
			if runtimePathContains(left.journal, right.journal) || runtimePathContains(right.journal, left.journal) {
				return errors.Config.Newf("auditlog %q journal overlaps auditlog %q journal", left.name, right.name)
			}
			if runtimePathContains(left.identityFile, right.identityFile) || runtimePathContains(right.identityFile, left.identityFile) {
				return errors.Config.Newf("auditlog %q identity file overlaps auditlog %q identity file", left.name, right.name)
			}
		}
		for _, other := range resolved {
			if runtimePathContains(left.identityFile, other.journal) || runtimePathContains(other.journal, left.identityFile) {
				return errors.Config.Newf("auditlog %q identity file overlaps auditlog %q journal", left.name, other.name)
			}
		}
	}
	return nil
}

func validateRecordingRuntimePathOverlaps(conf *configuration.Configuration, storage string) error {
	for recordingIndex, recordingAuditlog := range conf.Auditlogs {
		if !recordingAuditlog.Enabled || !recordingAuditlog.Recording.Enabled {
			continue
		}
		recordingDirectory := recordingAuditlog.Recording.Directory
		if storage != "" && runtimePathsOverlap(recordingDirectory, storage) {
			return errors.Config.Newf("auditlog %q recording directory overlaps session storage", recordingAuditlog.Name)
		}
		for auditlogIndex, auditlog := range conf.Auditlogs {
			if !auditlog.Enabled {
				continue
			}
			if runtimePathsOverlap(recordingDirectory, auditlog.Journal.Directory) {
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
		if !configured.Enabled || !configured.Recording.Enabled {
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
		if !auditlog.Enabled {
			continue
		}
		if storage != "" {
			if err := validateSessionStorageRuntimePath(storage, auditlog.IdentityFile, fmt.Sprintf("auditlog %q identity file", auditlog.Name)); err != nil {
				return err
			}
			if err := validateSessionStorageRuntimePath(storage, auditlog.Journal.Directory, fmt.Sprintf("auditlog %q journal", auditlog.Name)); err != nil {
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
	return validateRecordingRuntimePathOverlaps(conf, storage)
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
