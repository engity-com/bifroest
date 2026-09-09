package environment

import (
	"context"
	"fmt"
	gonet "net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

var _ = RegisterRepository(NewSshRepository)

const maxSshTargetChannels = 64

type sshResolvedSettings struct {
	address        bnet.HostPort
	user           string
	connectTimeout time.Duration
	forwardAllowed bool
	signers        []gossh.Signer
	cacheKey       string
}

type SshRepository struct {
	flow            configuration.FlowName
	conf            *configuration.EnvironmentSsh
	hostSigners     []gossh.Signer
	hostKeyCallback gossh.HostKeyCallback
	context         context.Context
	cancel          context.CancelFunc

	Logger log.Logger

	mutex      sync.Mutex
	transports map[connection.Id]*sshTransport
	attempts   map[connection.Id]*sshTransportAttempt
	closed     bool
}

func NewSshRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentSsh, _ alternatives.Provider, _ imp.Imp) (*SshRepository, error) {
	return newSshRepository(ctx, flow, conf, repositoryDependenciesFrom(ctx).hostKeys)
}

func NewSshRepositoryWithHostKeys(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentSsh, hostKeys []crypto.PrivateKey) (*SshRepository, error) {
	return newSshRepository(ctx, flow, conf, hostKeys)
}

func newSshRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentSsh, hostKeys []crypto.PrivateKey) (*SshRepository, error) {
	if conf == nil {
		return nil, fmt.Errorf("nil configuration")
	}
	var hostKeyCallback gossh.HostKeyCallback
	var err error
	if conf.AcceptAllHostKeys {
		hostKeyCallback = gossh.InsecureIgnoreHostKey()
		log.GetLogger("environment.ssh").Warn("SSH target host-key verification is disabled by acceptAllHostKeys")
	} else if hostKeyCallback, err = crypto.NewKnownHostsCallback(conf.KnownHosts, conf.KnownHostsFile); err != nil {
		return nil, err
	}
	hostSigners := make([]gossh.Signer, len(hostKeys))
	for i, key := range hostKeys {
		value := reflect.ValueOf(key)
		if key == nil || value.Kind() == reflect.Pointer && value.IsNil() {
			return nil, fmt.Errorf("nil SSH host key at index %d", i)
		}
		hostSigners[i] = key.ToSsh()
		if hostSigners[i] == nil {
			return nil, fmt.Errorf("SSH host key at index %d has no signer", i)
		}
	}
	repositoryContext, cancel := context.WithCancel(ctx)
	return &SshRepository{
		flow:            flow,
		conf:            conf,
		hostSigners:     hostSigners,
		hostKeyCallback: hostKeyCallback,
		context:         repositoryContext,
		cancel:          cancel,
		transports:      make(map[connection.Id]*sshTransport),
		attempts:        make(map[connection.Id]*sshTransportAttempt),
	}, nil
}

func (this *SshRepository) WillBeAccepted(ctx Context) (bool, error) {
	return this.conf.LoginAllowed.Render(ctx)
}

func (this *SshRepository) DoesSupportPty(Context, essh.Pty) (bool, error) {
	return true, nil
}

func (this *SshRepository) Ensure(req Request) (Environment, error) {
	accepted, err := this.WillBeAccepted(req)
	if err != nil {
		return nil, err
	}
	if !accepted {
		return nil, ErrNotAcceptable
	}
	sess := req.Authorization().FindSession()
	if sess == nil {
		return nil, errors.System.Newf("authorization without session")
	}
	settings, err := this.resolveSettings(req)
	if err != nil {
		return nil, err
	}
	lifetime, ok := connectionLifetime(req.Connection())
	if !ok {
		return nil, fmt.Errorf("SSH environment requires a connection with a lifetime context")
	}
	return &sshEnvironment{
		repository: this,
		connection: req.Connection(),
		lifetime:   lifetime,
		session:    sess,
		settings:   settings,
	}, nil
}

func (this *SshRepository) resolveSettings(req Request) (*sshResolvedSettings, error) {
	addressValue, err := this.conf.Address.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH target address: %w", err)
	}
	var address bnet.HostPort
	if err := address.Set(strings.TrimSpace(addressValue)); err != nil {
		return nil, fmt.Errorf("illegal rendered SSH target address %q: %w", addressValue, err)
	}
	if err := address.Validate(); err != nil {
		return nil, fmt.Errorf("illegal rendered SSH target address %q: %w", addressValue, err)
	}
	if address.IsZero() {
		return nil, fmt.Errorf("rendered SSH target address is empty")
	}
	user, err := this.conf.User.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH target user: %w", err)
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return nil, fmt.Errorf("rendered SSH target user is empty")
	}
	connectTimeout, err := this.conf.ConnectTimeout.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH connect timeout: %w", err)
	}
	if connectTimeout < 0 {
		return nil, fmt.Errorf("rendered SSH connect timeout cannot be negative")
	}
	forwardAllowed, err := this.conf.PortForwardingAllowed.Render(req)
	if err != nil {
		return nil, fmt.Errorf("cannot render SSH port forwarding setting: %w", err)
	}

	var signers []gossh.Signer
	identityKey := "fallback"
	if len(this.conf.IdentityFiles) > 0 {
		files, err := this.conf.IdentityFiles.Render(req)
		if err != nil {
			return nil, fmt.Errorf("cannot render SSH identity files: %w", err)
		}
		signers = make([]gossh.Signer, len(files))
		for i, file := range files {
			file = strings.TrimSpace(file)
			if file == "" {
				return nil, fmt.Errorf("rendered SSH identity file [%d] is empty", i)
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("cannot read SSH identity file %q: %w", file, err)
			}
			signer, err := gossh.ParsePrivateKey(raw)
			if err != nil {
				return nil, fmt.Errorf("cannot parse SSH identity file %q: %w", file, err)
			}
			signers[i] = signer
			identityKey += "\x00" + file + "\x00" + gossh.FingerprintSHA256(signer.PublicKey())
		}
	} else {
		signers = append([]gossh.Signer(nil), this.hostSigners...)
		for _, signer := range signers {
			identityKey += "\x00" + gossh.FingerprintSHA256(signer.PublicKey())
		}
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("no SSH client identity is available")
	}

	return &sshResolvedSettings{
		address:        address,
		user:           user,
		connectTimeout: connectTimeout,
		forwardAllowed: forwardAllowed,
		signers:        signers,
		cacheKey:       address.String() + "\x00" + user + "\x00" + connectTimeout.String() + "\x00" + identityKey,
	}, nil
}

func (this *SshRepository) FindBySession(context.Context, session.Session, *FindOpts) (Environment, error) {
	return nil, ErrNoSuchEnvironment
}

func (this *SshRepository) Cleanup(context.Context, *CleanupOpts) error { return nil }

func (this *SshRepository) transportFor(env *sshEnvironment, requestContexts ...context.Context) (*sshTransport, error) {
	id := env.connection.Id()
	requestContext := env.lifetime
	if len(requestContexts) > 0 && requestContexts[0] != nil {
		requestContext = requestContexts[0]
	}

	for {
		this.mutex.Lock()
		if this.closed {
			this.mutex.Unlock()
			return nil, fmt.Errorf("SSH environment repository is closed")
		}
		if existing := this.transports[id]; existing != nil {
			this.mutex.Unlock()
			if existing.cacheKey != env.settings.cacheKey {
				return nil, fmt.Errorf("SSH target settings changed within connection %s", id)
			}
			return existing, nil
		}
		if attempt := this.attempts[id]; attempt != nil {
			if attempt.cacheKey != env.settings.cacheKey {
				this.mutex.Unlock()
				return nil, fmt.Errorf("SSH target settings changed within connection %s", id)
			}
			this.mutex.Unlock()
			select {
			case <-attempt.done:
				continue
			case <-requestContext.Done():
				return nil, requestContext.Err()
			case <-env.lifetime.Done():
				return nil, env.lifetime.Err()
			case <-this.context.Done():
				return nil, fmt.Errorf("SSH environment repository is closed")
			}
		}
		attempt := &sshTransportAttempt{cacheKey: env.settings.cacheKey, done: make(chan struct{})}
		this.attempts[id] = attempt
		this.mutex.Unlock()

		dialContext, cancel := context.WithCancel(requestContext)
		stopLifetime := context.AfterFunc(env.lifetime, cancel)
		stopRepository := context.AfterFunc(this.context, cancel)
		transport, err := this.dial(dialContext, env.connection.Logger(), env.settings)
		stopLifetime()
		stopRepository()
		cancel()

		this.mutex.Lock()
		delete(this.attempts, id)
		usable := err == nil && !this.closed && env.lifetime.Err() == nil && requestContext.Err() == nil
		if usable {
			this.transports[id] = transport
		}
		close(attempt.done)
		this.mutex.Unlock()
		if err != nil {
			return nil, err
		}
		if !usable {
			_ = transport.Close()
			if err := env.lifetime.Err(); err != nil {
				return nil, err
			}
			if err := requestContext.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("SSH environment repository is closed")
		}

		go func() {
			_ = transport.client.Wait()
			this.removeTransport(id, transport)
		}()
		go func() {
			select {
			case <-env.lifetime.Done():
				this.removeTransport(id, transport)
			case <-transport.done:
			}
		}()
		return transport, nil
	}
}

func connectionLifetime(conn connection.Connection) (context.Context, bool) {
	if provider, ok := conn.(connection.LifetimeAware); ok {
		if result := provider.Lifetime(); result != nil {
			return result, true
		}
	}
	return nil, false
}

func (this *SshRepository) dial(lifetime context.Context, logger log.Logger, settings *sshResolvedSettings) (*sshTransport, error) {
	ctx := lifetime
	cancel := func() {}
	if settings.connectTimeout > 0 {
		ctx, cancel = context.WithTimeout(lifetime, settings.connectTimeout)
	}
	defer cancel()

	raw, err := (&gonet.Dialer{}).DialContext(ctx, "tcp", settings.address.String())
	if err != nil {
		return nil, fmt.Errorf("cannot connect to SSH target %s: %w", settings.address, err)
	}
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("cannot configure SSH handshake deadline: %w", err)
		}
	}
	handshakeDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = raw.Close()
		case <-handshakeDone:
		}
	}()
	clientConn, channels, requests, err := gossh.NewClientConn(raw, settings.address.String(), &gossh.ClientConfig{
		User:            settings.user,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(settings.signers...)},
		HostKeyCallback: this.hostKeyCallback,
	})
	close(handshakeDone)
	<-watcherDone
	if err != nil {
		return nil, fmt.Errorf("cannot establish SSH target connection to %s: %w", settings.address, err)
	}
	if err := ctx.Err(); err != nil {
		_ = clientConn.Close()
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		_ = clientConn.Close()
		return nil, fmt.Errorf("cannot clear SSH handshake deadline: %w", err)
	}
	success = true
	logger.With("target", settings.address).With("user", settings.user).Debug("SSH target connection established")
	return newSshTransport(gossh.NewClient(clientConn, channels, requests), settings.cacheKey), nil
}

func (this *SshRepository) removeTransport(id connection.Id, transport *sshTransport) {
	this.mutex.Lock()
	if this.transports[id] == transport {
		delete(this.transports, id)
	}
	this.mutex.Unlock()
	_ = transport.Close()
}

func (this *SshRepository) Close() error {
	this.cancel()
	this.mutex.Lock()
	if this.closed {
		this.mutex.Unlock()
		return nil
	}
	this.closed = true
	transports := make([]*sshTransport, 0, len(this.transports))
	for _, transport := range this.transports {
		transports = append(transports, transport)
	}
	clear(this.transports)
	this.mutex.Unlock()
	var result error
	for _, transport := range transports {
		if err := transport.Close(); err != nil && result == nil {
			result = err
		}
	}
	return result
}

type sshTransportAttempt struct {
	cacheKey string
	done     chan struct{}
}

type sshTransport struct {
	client   *gossh.Client
	cacheKey string
	done     chan struct{}
	channels chan struct{}

	closeOnce sync.Once
	agentMu   sync.Mutex
	agent     *sshAgentBridge
}

func newSshTransport(client *gossh.Client, cacheKey string) *sshTransport {
	return &sshTransport{client: client, cacheKey: cacheKey, done: make(chan struct{}), channels: make(chan struct{}, maxSshTargetChannels)}
}

func (this *sshTransport) acquireChannel(ctx context.Context) error {
	select {
	case this.channels <- struct{}{}:
		select {
		case <-this.done:
			this.releaseChannel()
			return fmt.Errorf("SSH target transport is closed")
		default:
			return nil
		}
	case <-this.done:
		return fmt.Errorf("SSH target transport is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (this *sshTransport) tryAcquireChannel() bool {
	select {
	case <-this.done:
		return false
	default:
	}
	select {
	case this.channels <- struct{}{}:
		select {
		case <-this.done:
			this.releaseChannel()
			return false
		default:
			return true
		}
	default:
		return false
	}
}

func (this *sshTransport) releaseChannel() {
	<-this.channels
}

func (this *sshTransport) Close() (result error) {
	this.closeOnce.Do(func() {
		this.agentMu.Lock()
		if this.agent != nil {
			result = this.agent.Close()
		}
		this.agentMu.Unlock()
		if err := this.client.Close(); err != nil && result == nil {
			result = err
		}
		close(this.done)
	})
	return result
}
