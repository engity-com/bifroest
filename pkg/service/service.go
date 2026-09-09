package service

import (
	"context"
	goerrors "errors"
	"fmt"
	gonet "net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/alternatives"
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
			l := this.logger().With("address", ln.addr)
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

	ctx := context.Background()
	svc = &service{Service: this, connectionLifecycle: newConnectionLifecycle()}

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

	if svc.alternatives, err = alternatives.NewProvider(ctx, this.Version, &this.Configuration.Alternatives); err != nil {
		return fail(err)
	}
	if svc.imp, err = imp.NewImp(ctx, hostSigners[0]); err != nil {
		return fail(err)
	}
	if svc.sessions, err = session.NewFacadeRepository(ctx, &this.Configuration.Session); err != nil {
		return fail(err)
	}
	if svc.authorizer, err = authorization.NewAuthorizerFacade(ctx, &this.Configuration.Flows); err != nil {
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

	return svc, nil
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
	kc := &this.Configuration.Ssh.Keys

	hostKeys, err := kc.HostKeys.Render(noopContext{})
	if err != nil {
		return nil, errors.Config.Newf("cannot render hostKeys: %w", err)
	}

	var result []crypto.PrivateKey
	for _, fn := range hostKeys {
		if fn == "" {
			continue
		}
		pk, err := crypto.EnsureKeyFile(fn, &crypto.KeyRequirement{
			Type: crypto.KeyTypeEd25519,
		}, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot ensure host key: %w", err)
		}

		if ok, err := kc.KeyAllowed(pk); err != nil {
			return nil, fmt.Errorf("cannot check if host key %q is allowed or not: %w", fn, err)
		} else if !ok {
			return nil, fmt.Errorf("cannot check if host key %q is not allowed by restrictions: %w", fn, err)
		}
		result = append(result, pk)
	}
	return result, nil
}

type service struct {
	*Service

	sessions       session.CloseableRepository
	authorizer     authorization.CloseableAuthorizer
	environments   environment.CloseableRepository
	houseKeeper    houseKeeper
	alternatives   alternatives.Provider
	imp            imp.Imp
	server         essh.Server
	forwardHandler essh.ForwardedTCPHandler

	knownFlows map[configuration.FlowName]struct{}

	resolvedSshKeysExchanges           []string
	resolvedSshMessagesAuthentications []string
	resolvedSshMessagesCiphers         []string

	activeConnections   atomic.Int64
	connectionLifecycle *connectionLifecycle
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
	return nil
}

func sshMaxAuthTries(value uint8) int {
	if value == 0 {
		return -1
	}
	return int(value)
}

func (this *service) Close() (rErr error) {
	defer common.KeepCloseError(&rErr, this.alternatives)
	defer common.KeepCloseError(&rErr, this.imp)
	defer common.KeepCloseError(&rErr, this.sessions)
	defer common.KeepCloseError(&rErr, this.authorizer)
	defer common.KeepCloseError(&rErr, this.environments)
	defer common.KeepCloseError(&rErr, &this.houseKeeper)
	return nil
}
