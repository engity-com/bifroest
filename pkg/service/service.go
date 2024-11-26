package service

import (
	"context"
	"fmt"
	gonet "net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	glssh "github.com/gliderlabs/ssh"
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
	connectionCtxKey    = struct{ uint64 }{83439637}
	authorizationCtxKey = struct{ uint64 }{10282643}
	handshakeKeyCtxKey  = struct{ uint64 }{30072498}
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
	defer common.KeepCloseError(&rErr, svc)

	lns := make([]struct {
		ln   gonet.Listener
		addr bnet.Address
	}, len(this.Configuration.Ssh.Addresses))
	var lnMutex sync.Mutex
	closeLns := func() {
		lnMutex.Lock()
		defer lnMutex.Unlock()

		for _, ln := range lns {
			if ln.ln != nil {
				//goland:noinspection GoDeferInLoop
				defer func(target *gonet.Listener) {
					*target = nil
				}(&ln.ln)
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

	done := make(chan error, len(lns))
	var wg sync.WaitGroup
	for _, ln := range lns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := this.logger().With("address", ln.addr)

			l.Info("listening...")
			if err := svc.server.Serve(ln.ln); this.isProblematicError(err) {
				l.WithError(err).Error("listening... FAILED!")
				done <- err
				return
			}
			l.Info("listening... DONE!")
			done <- nil
		}()
	}

	go func() {
		for {
			select {
			case err, ok := <-done:
				if !ok {
					return
				}
				if this.isProblematicError(err) && rErr == nil {
					rErr = err
				}
				closeLns()
			case <-ctx.Done():
				closeLns()
			}
		}
	}()
	wg.Wait()

	close(done)

	return
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
	svc = &service{Service: this}

	svc.knownFlows = make(map[configuration.FlowName]struct{})
	for _, flow := range this.Configuration.Flows {
		svc.knownFlows[flow.Name] = struct{}{}
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
	if svc.environments, err = environment.NewRepositoryFacade(ctx, &this.Configuration.Flows, svc.alternatives, svc.imp); err != nil {
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
	svc.server.IdleTimeout = 0 // handled by service's connection
	svc.server.MaxTimeout = 0  // handled by service's connection
	svc.server.ServerConfigCallback = svc.createNewServerConfig
	svc.server.ConnCallback = svc.onNewConnConnection
	svc.server.Handler = svc.handleSshShellSession
	svc.server.PtyCallback = svc.onPtyRequest
	svc.server.ReversePortForwardingCallback = svc.onReversePortForwardingRequested
	svc.server.PublicKeyHandler = svc.handlePublicKey
	svc.server.PasswordHandler = svc.handlePassword
	svc.server.KeyboardInteractiveHandler = svc.handleKeyboardInteractiveChallenge
	svc.server.BannerHandler = svc.handleBanner
	svc.server.RequestHandlers = map[string]glssh.RequestHandler{
		"tcpip-forward":        svc.forwardHandler.HandleSSHRequest,
		"cancel-tcpip-forward": svc.forwardHandler.HandleSSHRequest,
	}
	svc.server.ChannelHandlers = map[string]glssh.ChannelHandler{
		"session":      svc.handleNewSshSession,
		"direct-tcpip": svc.handleNewDirectTcpIp,
	}
	svc.server.SubsystemHandlers = map[string]glssh.SubsystemHandler{
		"sftp": svc.handleSshSftpSession,
	}
	svc.server.HostSigners = make([]glssh.Signer, len(hostPrivateKeys))
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
	server         glssh.Server
	forwardHandler glssh.ForwardedTCPHandler

	knownFlows map[configuration.FlowName]struct{}

	activeConnections atomic.Int64
}

func withLazyContextOrFieldExclude[C any](ctx glssh.Context, ctxKey any) fields.Lazy {
	return fields.LazyFunc(func() any {
		if v, ok := ctx.Value(ctxKey).(C); ok {
			return v
		}
		return fields.Exclude
	})
}

func (this *service) connection(ctx glssh.Context) *connection {
	if v, ok := ctx.Value(connectionCtxKey).(*connection); ok {
		return v
	}
	return nil
}

func (this *service) logger(ctx glssh.Context) log.Logger {
	if v := this.connection(ctx); v != nil {
		return v.Logger()
	}
	return this.Service.logger()
}

func (this *service) isSilentError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func (this *service) isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !sys.IsClosedError(err)
}

func (this *service) createNewServerConfig(glssh.Context) *gossh.ServerConfig {
	return &gossh.ServerConfig{
		ServerVersion: "SSH-2.0-Engity-Bifroest_" + this.Version.Version(),
		MaxAuthTries:  int(this.Configuration.Ssh.MaxAuthTries),
	}
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
