package environment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	gonet "net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestSshEnvironmentSharesTransportForExecSftpAndDirectTcpIp(t *testing.T) {
	target := newSshTarget(t)
	defer target.Close()

	ctx, cancel := newSshTestContext()
	defer cancel()
	conn := &sshTestConnection{id: connection.MustNewId(), context: ctx}
	sess := &sshTestStoredSession{id: session.MustNewId()}
	auth := &sshTestAuthorization{session: sess, environment: sys.EnvVars{"LAYER": "authorization", "SSH_ORIGINAL_COMMAND": "forged-by-authorization"}}
	hostKey := newSshTestPrivateKey(t)
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString(target.Address())
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	repositoryContext := context.WithValue(context.Background(), repositoryDependenciesContextKey{}, repositoryDependencies{hostKeys: []crypto.PrivateKey{hostKey}})
	repository, err := NewSshRepository(repositoryContext, "test", conf, nil, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()

	execSession := newSshTestSession(ctx, "show-environment", nil)
	execSession.originalCommand = "trusted-original-command"
	execSession.hasOriginalCommand = true
	execTask := &sshTestTask{
		context: ctx, connection: conn, authorization: auth, session: execSession,
		taskType: TaskTypeShell,
		environmentVariables: configuration.EnvironmentVariables{
			"LAYER":                template.MustNewString("flow"),
			"SSH_ORIGINAL_COMMAND": template.MustNewString("forged-by-flow"),
		},
	}
	resolved, err := repository.Ensure(execTask)
	require.NoError(t, err)
	environment := resolved.(*sshEnvironment)
	type transportResult struct {
		transport *sshTransport
		err       error
	}
	transports := make(chan transportResult, 16)
	var transportWorkers sync.WaitGroup
	for range 16 {
		transportWorkers.Add(1)
		go func() {
			defer transportWorkers.Done()
			transport, err := repository.transportFor(environment)
			transports <- transportResult{transport, err}
		}()
	}
	transportWorkers.Wait()
	close(transports)
	var sharedTransport *sshTransport
	for result := range transports {
		require.NoError(t, result.err)
		if sharedTransport == nil {
			sharedTransport = result.transport
		}
		require.Same(t, sharedTransport, result.transport)
	}
	_, _, err = environment.openTargetChannel(ctx, sharedTransport, "unsupported", nil)
	var rejection *gossh.OpenChannelError
	require.ErrorAs(t, err, &rejection)
	transportAfterRejection, err := repository.transportFor(environment)
	require.NoError(t, err)
	require.Same(t, sharedTransport, transportAfterRejection)

	exitCode, err := environment.Run(execTask)
	require.NoError(t, err)
	require.Equal(t, 7, exitCode)
	require.Contains(t, execSession.stdout.String(), "command=show-environment")
	require.Contains(t, execSession.stdout.String(), "LAYER=flow")
	require.Contains(t, execSession.stdout.String(), session.EnvName+"="+sess.id.String())
	require.Contains(t, execSession.stdout.String(), "SSH_ORIGINAL_COMMAND=trusted-original-command")
	require.Equal(t, "target stderr", execSession.stderr.String())

	sftpSession := newSshTestSession(ctx, "", []byte("sftp-payload"))
	sftpTask := &sshTestTask{context: ctx, connection: conn, authorization: auth, session: sftpSession, taskType: TaskTypeSftp}
	exitCode, err = environment.Run(sftpTask)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)
	require.Equal(t, "sftp-payload", sftpSession.stdout.String())

	destination, err := environment.NewDestinationConnection(ctx, bnet.MustNewHostPort("example.org:443"))
	require.NoError(t, err)
	_, err = destination.Write([]byte("forwarded"))
	require.NoError(t, err)
	require.NoError(t, destination.(interface{ CloseWrite() error }).CloseWrite())
	forwarded, err := io.ReadAll(destination)
	require.NoError(t, err)
	require.Equal(t, "forwarded", string(forwarded))
	_ = destination.Close()

	require.Equal(t, int32(1), target.connections.Load())
	cancel()
	require.Eventually(t, func() bool {
		repository.mutex.Lock()
		defer repository.mutex.Unlock()
		return len(repository.transports) == 0
	}, time.Second, 10*time.Millisecond)
}

func TestSshEnvironmentCancellationDoesNotCloseSharedTransport(t *testing.T) {
	target := newSshTarget(t)
	defer target.Close()

	connectionContext, cancelConnection := newSshTestContext()
	defer cancelConnection()
	conn := &sshTestConnection{id: connection.MustNewId(), context: connectionContext}
	sess := &sshTestStoredSession{id: session.MustNewId()}
	auth := &sshTestAuthorization{session: sess}
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString(target.Address())
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()

	taskContext, cancelTask := newSshTestContext()
	blockedSession := newSshTestSession(taskContext, "block-request", nil)
	blockedTask := &sshTestTask{context: taskContext, connection: conn, authorization: auth, session: blockedSession, taskType: TaskTypeShell}
	resolved, err := repository.Ensure(blockedTask)
	require.NoError(t, err)
	blockedEnvironment := resolved.(*sshEnvironment)
	transport, err := repository.transportFor(blockedEnvironment)
	require.NoError(t, err)
	type runResult struct {
		code int
		err  error
	}
	runDone := make(chan runResult, 1)
	go func() {
		code, err := blockedEnvironment.Run(blockedTask)
		runDone <- runResult{code, err}
	}()
	select {
	case <-target.blockedExec:
	case <-time.After(time.Second):
		t.Fatal("target did not receive blocked exec request")
	}
	cancelTask()
	select {
	case result := <-runDone:
		require.Equal(t, -1, result.code)
		require.ErrorIs(t, result.err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("canceled SSH task did not return")
	}
	require.Eventually(t, func() bool { return len(transport.channels) == 0 }, time.Second, 10*time.Millisecond)

	remaining, err := repository.transportFor(blockedEnvironment)
	require.NoError(t, err)
	require.Same(t, transport, remaining)
	require.Equal(t, int32(1), target.connections.Load())
}

func TestSshEnvironmentPersistsUserCertificateAcrossConnectionsAndCaRotation(t *testing.T) {
	originalCa := newSshTestPrivateKey(t)
	rotatedCa := newSshTestPrivateKey(t)
	originalCaFingerprint := gossh.FingerprintSHA256(originalCa.ToSsh().PublicKey())
	receivedCertificates := make(chan *gossh.Certificate, 2)
	checker := gossh.CertChecker{
		IsUserAuthority: func(key gossh.PublicKey) bool {
			return gossh.FingerprintSHA256(key) == originalCaFingerprint
		},
	}
	target := newSshTargetWithPublicKeyCallback(t, func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		if certificate, ok := key.(*gossh.Certificate); ok {
			receivedCertificates <- certificate
		}
		return checker.Authenticate(conn, key)
	})
	defer target.Close()

	directory := t.TempDir()
	subjectFile := filepath.Join(directory, "subject")
	originalCaFile := filepath.Join(directory, "ca")
	rotatedCaFile := filepath.Join(directory, "rotated-ca")
	writeSshTestPrivateKey(t, originalCaFile, originalCa)
	writeSshTestPrivateKey(t, rotatedCaFile, rotatedCa)

	newConfiguration := func(authorityFile string) *configuration.EnvironmentSsh {
		conf := &configuration.EnvironmentSsh{}
		require.NoError(t, conf.SetDefaults())
		conf.Address = template.MustNewString(target.Address())
		conf.User = template.MustNewString("target-user")
		conf.AcceptAllHostKeys = true
		certificate := &configuration.EnvironmentSshCertificate{}
		require.NoError(t, certificate.SetDefaults())
		certificate.IdentityFile = template.MustNewString(subjectFile)
		certificate.AuthorityIdentityFile = template.MustNewString(authorityFile)
		certificate.Validity = template.DurationOf(time.Hour)
		certificate.Extensions = configuration.EnvironmentSshCertificateExtensions{
			"permit-pty":             template.MustNewString(""),
			"audit-role@example.org": template.MustNewString("production"),
		}
		conf.Certificate = certificate
		return conf
	}

	storedSession := &sshTestStoredSession{id: session.MustNewId()}
	firstContext, cancelFirst := newSshTestContext()
	defer cancelFirst()
	firstTask := &sshTestTask{
		context:       firstContext,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: firstContext},
		authorization: &sshTestAuthorization{session: storedSession},
		session:       newSshTestSession(firstContext, "true", nil),
		taskType:      TaskTypeShell,
	}
	firstRepository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", newConfiguration(originalCaFile), []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)

	const workers = 16
	environments := make(chan *sshEnvironment, workers)
	errorsFromEnsure := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			resolved, err := firstRepository.Ensure(firstTask)
			if err != nil {
				errorsFromEnsure <- err
				return
			}
			environments <- resolved.(*sshEnvironment)
		}()
	}
	wait.Wait()
	close(environments)
	close(errorsFromEnsure)
	for err := range errorsFromEnsure {
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), storedSession.environmentTokenWrites.Load())
	require.FileExists(t, subjectFile)
	firstEnvironment := <-environments
	firstTransport, err := firstRepository.transportFor(firstEnvironment)
	require.NoError(t, err)
	firstCertificate := <-receivedCertificates
	require.EqualValues(t, gossh.UserCert, firstCertificate.CertType)
	require.Equal(t, []string{"target-user"}, firstCertificate.ValidPrincipals)
	require.Equal(t, storedSession.id.String(), firstCertificate.Extensions["session-id@bifroest.engity.org"])
	require.Equal(t, "production", firstCertificate.Extensions["audit-role@example.org"])
	evidence := firstCertificate.Extensions["evidence-v1@bifroest.engity.org"]
	require.Contains(t, evidence, `"schema":"bifroest.authorization-evidence/v1"`)
	require.NotContains(t, strings.ToLower(evidence), "password")
	require.NotContains(t, strings.ToLower(evidence), "token")
	require.Equal(t, originalCaFingerprint, gossh.FingerprintSHA256(firstCertificate.SignatureKey))
	firstCertificateBytes := firstCertificate.Marshal()
	storedToken, err := storedSession.EnvironmentToken(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, storedToken)
	storedState, err := decodeSshUserCertificateState(storedToken)
	require.NoError(t, err)
	require.Equal(t, time.Hour, storedState.MaxValidUntil.Sub(storedState.IssuedAt))
	compatible, err := firstRepository.IsSessionCompatible(context.Background(), storedSession)
	require.NoError(t, err)
	require.True(t, compatible)
	_, err = firstRepository.validateUserCertificateState(storedState, storedSession, firstEnvironment.settings, storedState.MaxValidUntil)
	require.ErrorContains(t, err, "expired")
	require.NoError(t, firstTransport.Close())
	require.NoError(t, firstRepository.Close())

	secondContext, cancelSecond := newSshTestContext()
	defer cancelSecond()
	secondTask := &sshTestTask{
		context:       secondContext,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: secondContext},
		authorization: &sshTestAuthorization{session: storedSession},
		session:       newSshTestSession(secondContext, "true", nil),
		taskType:      TaskTypeShell,
	}
	rotatedConfiguration := newConfiguration(rotatedCaFile)
	rotatedConfiguration.Certificate.Validity = template.DurationOf(48 * time.Hour)
	secondRepository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", rotatedConfiguration, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	defer func() { require.NoError(t, secondRepository.Close()) }()
	compatible, err = secondRepository.IsSessionCompatible(context.Background(), storedSession)
	require.NoError(t, err)
	require.True(t, compatible)
	resolved, err := secondRepository.Ensure(secondTask)
	require.NoError(t, err)
	_, err = secondRepository.transportFor(resolved.(*sshEnvironment))
	require.NoError(t, err)
	secondCertificate := <-receivedCertificates
	require.Equal(t, firstCertificateBytes, secondCertificate.Marshal())
	storedTokenAfterRestart, err := storedSession.EnvironmentToken(context.Background())
	require.NoError(t, err)
	require.Equal(t, storedToken, storedTokenAfterRestart)
	require.Equal(t, int32(1), storedSession.environmentTokenWrites.Load())
	changedConfiguration := newConfiguration(rotatedCaFile)
	delete(changedConfiguration.Certificate.Extensions, "audit-role@example.org")
	changedRepository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", changedConfiguration, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	compatible, err = changedRepository.IsSessionCompatible(context.Background(), storedSession)
	require.NoError(t, err)
	require.False(t, compatible)
	require.NoError(t, changedRepository.Close())

	restoredEnvironment, err := secondRepository.FindBySession(context.Background(), storedSession, nil)
	require.NoError(t, err)
	disposed, err := restoredEnvironment.Dispose(context.Background())
	require.NoError(t, err)
	require.True(t, disposed)
	remainingToken, err := storedSession.EnvironmentToken(context.Background())
	require.NoError(t, err)
	require.Empty(t, remainingToken)
}

func TestSshPtyRequestsPreservePixelDimensions(t *testing.T) {
	sender := &sshTestRequestSender{accepted: true}
	pty := essh.Pty{
		Term:          "xterm",
		Window:        essh.Window{Width: 120, Height: 40, WidthPixels: 1920, HeightPixels: 1080},
		TerminalModes: gossh.TerminalModes{gossh.ECHO: 0},
	}
	require.NoError(t, requestTargetPty(sender, pty))
	require.Equal(t, "pty-req", sender.name)
	var initial struct {
		Term         string
		Columns      uint32
		Rows         uint32
		WidthPixels  uint32
		HeightPixels uint32
		Modelist     string
	}
	require.NoError(t, gossh.Unmarshal(sender.payload, &initial))
	require.Equal(t, uint32(1920), initial.WidthPixels)
	require.Equal(t, uint32(1080), initial.HeightPixels)

	window := essh.Window{Width: 80, Height: 24, WidthPixels: 1280, HeightPixels: 720}
	require.NoError(t, sendTargetWindowChange(sender, window))
	require.Equal(t, "window-change", sender.name)
	var changed struct {
		Columns      uint32
		Rows         uint32
		WidthPixels  uint32
		HeightPixels uint32
	}
	require.NoError(t, gossh.Unmarshal(sender.payload, &changed))
	require.Equal(t, uint32(1280), changed.WidthPixels)
	require.Equal(t, uint32(720), changed.HeightPixels)
}

func TestNewSshRepositoryWithHostKeysRejectsNilKey(t *testing.T) {
	conf := &configuration.EnvironmentSsh{AcceptAllHostKeys: true}
	_, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{nil})
	require.ErrorContains(t, err, "nil SSH host key")
}

func TestSshCertificateUsesFirstHostKeyAsAuthorityFallback(t *testing.T) {
	hostKey := newSshTestPrivateKey(t)
	conf := newSshCertificateTestConfiguration(t, filepath.Join(t.TempDir(), "subject"), "")
	repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{hostKey, newSshTestPrivateKey(t)})
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	require.Equal(t, gossh.FingerprintSHA256(hostKey.ToSsh().PublicKey()), repository.certificateKeys.authorityFingerprint)
}

func TestSshCertificateRejectsInvalidExistingKeys(t *testing.T) {
	directory := t.TempDir()
	hostKey := newSshTestPrivateKey(t)
	for _, test := range []struct {
		name      string
		subject   string
		authority string
	}{
		{name: "subject", subject: "invalid", authority: ""},
		{name: "authority", subject: "", authority: "invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			subjectFile := filepath.Join(directory, test.name+"-subject")
			authorityFile := ""
			if test.subject != "" {
				require.NoError(t, os.WriteFile(subjectFile, []byte(test.subject), 0600))
			}
			if test.authority != "" {
				authorityFile = filepath.Join(directory, test.name+"-authority")
				require.NoError(t, os.WriteFile(authorityFile, []byte(test.authority), 0600))
			}
			conf := newSshCertificateTestConfiguration(t, subjectFile, authorityFile)
			_, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{hostKey})
			require.Error(t, err)
		})
	}
}

func TestSshCertificateSessionCompatibilityUsesCurrentAuthorizationContext(t *testing.T) {
	conf := newSshCertificateTestConfiguration(t, filepath.Join(t.TempDir(), "subject"), "")
	conf.User = template.MustNewString("{{ .targetUser }}")
	conf.Certificate.Principals = template.MustNewStrings("{{ .targetUser }}")
	conf.Certificate.Extensions = configuration.EnvironmentSshCertificateExtensions{
		"permit-port-forwarding": template.MustNewString(""),
	}
	repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()

	ctx, cancel := newSshTestContext()
	defer cancel()
	storedSession := &sshTestStoredSession{id: session.MustNewId()}
	base := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: storedSession, kind: "simple"},
		session:       newSshTestSession(ctx, "true", nil),
		taskType:      TaskTypeShell,
		targetUser:    "target-user",
	}
	_, err = repository.Ensure(base)
	require.NoError(t, err)
	compatible, err := repository.IsSessionCompatibleWith(base, storedSession)
	require.NoError(t, err)
	require.True(t, compatible)

	changedUser := *base
	changedUser.targetUser = "other-user"
	compatible, err = repository.IsSessionCompatibleWith(&changedUser, storedSession)
	require.NoError(t, err)
	require.False(t, compatible)

	changedKind := *base
	changedKind.authorization = &sshTestAuthorization{session: storedSession, kind: "htpasswd"}
	compatible, err = repository.IsSessionCompatibleWith(&changedKind, storedSession)
	require.NoError(t, err)
	require.False(t, compatible)

	changedPolicy := *base
	changedPolicy.authorization = &sshTestAuthorization{
		session: storedSession,
		kind:    "simple",
		policy:  &authorization.AuthorizedKeyPolicy{PtyAllowed: true, PortForwardingAllowed: false, AgentForwardingAllowed: true},
	}
	compatible, err = repository.IsSessionCompatibleWith(&changedPolicy, storedSession)
	require.NoError(t, err)
	require.False(t, compatible)
}

func TestSshRepositoryRejectsEmptyRenderedAddress(t *testing.T) {
	ctx, cancel := newSshTestContext()
	defer cancel()
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString("   ")
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	storedSession := &sshTestStoredSession{id: session.MustNewId()}
	task := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: storedSession},
		session:       newSshTestSession(ctx, "true", nil),
		taskType:      TaskTypeShell,
	}
	_, err = repository.resolveSettings(task)
	require.ErrorContains(t, err, "address is empty")
}

func TestSshEnvironmentRejectsReversePortForwarding(t *testing.T) {
	environment := &sshEnvironment{}
	allowed, err := environment.IsReversePortForwardingAllowed(bnet.MustNewHostPort("127.0.0.1:2222"))
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestCollectSftpExitStatusRequiresStatus(t *testing.T) {
	requests := make(chan *gossh.Request)
	close(requests)
	status, err := collectSftpExitStatus(requests)
	require.Equal(t, -1, status)
	require.ErrorContains(t, err, "did not report an exit status")
}

type sshTestRequestSender struct {
	name     string
	payload  []byte
	accepted bool
}

func (this *sshTestRequestSender) SendRequest(name string, _ bool, payload []byte) (bool, error) {
	this.name = name
	this.payload = append([]byte(nil), payload...)
	return this.accepted, nil
}

type sshTarget struct {
	listener    gonet.Listener
	config      *gossh.ServerConfig
	connections atomic.Int32
	done        chan struct{}
	closeOnce   sync.Once
	blockedExec chan struct{}
}

func newSshTarget(t *testing.T) *sshTarget {
	return newSshTargetWithPublicKeyCallback(t, nil)
}

func newSshTargetWithPublicKeyCallback(t *testing.T, callback func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error)) *sshTarget {
	t.Helper()
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	config := &gossh.ServerConfig{NoClientAuth: callback == nil, PublicKeyCallback: callback}
	config.AddHostKey(newSshTestSigner(t))
	result := &sshTarget{
		listener: listener, config: config, done: make(chan struct{}),
		blockedExec: make(chan struct{}, 1),
	}
	go result.serve()
	return result
}

func (this *sshTarget) Address() string { return this.listener.Addr().String() }

func (this *sshTarget) Close() {
	this.closeOnce.Do(func() {
		close(this.done)
		_ = this.listener.Close()
	})
}

func (this *sshTarget) serve() {
	for {
		raw, err := this.listener.Accept()
		if err != nil {
			return
		}
		this.connections.Add(1)
		go this.serveConnection(raw)
	}
}

func (this *sshTarget) serveConnection(raw gonet.Conn) {
	connection, channels, requests, err := gossh.NewServerConn(raw, this.config)
	if err != nil {
		_ = raw.Close()
		return
	}
	defer func() { _ = connection.Close() }()
	go gossh.DiscardRequests(requests)
	for channel := range channels {
		switch channel.ChannelType() {
		case "session":
			go serveSshTargetSession(channel, this.blockedExec)
		case "direct-tcpip":
			go serveSshTargetForward(channel)
		default:
			_ = channel.Reject(gossh.UnknownChannelType, "unsupported")
		}
	}
}

func serveSshTargetSession(channel gossh.NewChannel, blockedExec chan<- struct{}) {
	stream, requests, err := channel.Accept()
	if err != nil {
		return
	}
	environment := make(map[string]string)
	for request := range requests {
		switch request.Type {
		case "env":
			var payload struct {
				Name  string
				Value string
			}
			if gossh.Unmarshal(request.Payload, &payload) == nil {
				environment[payload.Name] = payload.Value
			}
			_ = request.Reply(true, nil)
		case "exec":
			var payload struct{ Command string }
			_ = gossh.Unmarshal(request.Payload, &payload)
			if payload.Command == "block-request" {
				blockedExec <- struct{}{}
				continue
			}
			_ = request.Reply(true, nil)
			_, _ = io.WriteString(stream, "command="+payload.Command+" LAYER="+environment["LAYER"]+" "+session.EnvName+"="+environment[session.EnvName]+" SSH_ORIGINAL_COMMAND="+environment["SSH_ORIGINAL_COMMAND"])
			_, _ = io.WriteString(stream.Stderr(), "target stderr")
			_, _ = stream.SendRequest("exit-status", false, gossh.Marshal(&struct{ Status uint32 }{7}))
			_ = stream.Close()
			return
		case "subsystem":
			var payload struct{ Subsystem string }
			_ = gossh.Unmarshal(request.Payload, &payload)
			accepted := payload.Subsystem == "sftp"
			_ = request.Reply(accepted, nil)
			if !accepted {
				_ = stream.Close()
				return
			}
			_, _ = io.Copy(stream, stream)
			_, _ = stream.SendRequest("exit-status", false, gossh.Marshal(&struct{ Status uint32 }{0}))
			_ = stream.Close()
			return
		default:
			_ = request.Reply(false, nil)
		}
	}
	_ = stream.Close()
}

func serveSshTargetForward(channel gossh.NewChannel) {
	stream, requests, err := channel.Accept()
	if err != nil {
		return
	}
	go gossh.DiscardRequests(requests)
	_, _ = io.Copy(stream, stream)
	_ = stream.Close()
}

func newSshTestPrivateKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	result, err := crypto.PrivateKeyFromSdk(private)
	require.NoError(t, err)
	return result
}

func newSshTestSigner(t *testing.T) gossh.Signer { return newSshTestPrivateKey(t).ToSsh() }

func writeSshTestPrivateKey(t *testing.T, path string, key crypto.PrivateKey) {
	t.Helper()
	var content bytes.Buffer
	require.NoError(t, crypto.WriteSshPrivateKey(key, &content))
	require.NoError(t, os.WriteFile(path, content.Bytes(), 0600))
}

func newSshCertificateTestConfiguration(t *testing.T, subjectFile, authorityFile string) *configuration.EnvironmentSsh {
	t.Helper()
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString("target.example.org:22")
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	certificate := &configuration.EnvironmentSshCertificate{}
	require.NoError(t, certificate.SetDefaults())
	certificate.IdentityFile = template.MustNewString(subjectFile)
	certificate.AuthorityIdentityFile = template.MustNewString(authorityFile)
	certificate.Validity = template.DurationOf(time.Hour)
	conf.Certificate = certificate
	return conf
}

type sshTestContext struct {
	context.Context
	sync.Mutex
	values      map[any]any
	permissions essh.Permissions
}

func newSshTestContext() (*sshTestContext, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return &sshTestContext{Context: ctx, values: make(map[any]any)}, cancel
}

func (this *sshTestContext) User() string                   { return "source-user" }
func (this *sshTestContext) SessionID() string              { return "test-session" }
func (this *sshTestContext) ClientVersion() string          { return "test-client" }
func (this *sshTestContext) ServerVersion() string          { return "test-server" }
func (this *sshTestContext) RemoteAddr() gonet.Addr         { return sshTestAddress("remote") }
func (this *sshTestContext) LocalAddr() gonet.Addr          { return sshTestAddress("local") }
func (this *sshTestContext) Permissions() *essh.Permissions { return &this.permissions }
func (this *sshTestContext) SetValue(key, value any)        { this.values[key] = value }
func (this *sshTestContext) Value(key any) any {
	if value, ok := this.values[key]; ok {
		return value
	}
	return this.Context.Value(key)
}

type sshTestAddress string

func (this sshTestAddress) Network() string { return "test" }
func (this sshTestAddress) String() string  { return string(this) }

type sshTestRemote struct{}

func (sshTestRemote) User() string    { return "source-user" }
func (sshTestRemote) Host() bnet.Host { return bnet.MustNewHost("127.0.0.1") }
func (sshTestRemote) String() string  { return "source-user@127.0.0.1" }

type sshTestConnection struct {
	id      connection.Id
	context *sshTestContext
}

func (this *sshTestConnection) Id() connection.Id         { return this.id }
func (this *sshTestConnection) Remote() bnet.Remote       { return sshTestRemote{} }
func (this *sshTestConnection) Logger() log.Logger        { return log.GetLogger("test.ssh-environment") }
func (this *sshTestConnection) Lifetime() context.Context { return this.context }

type sshTestStoredSession struct {
	id                     session.Id
	mutex                  sync.Mutex
	environmentToken       []byte
	environmentTokenWrites atomic.Int32
}

func (*sshTestStoredSession) Flow() configuration.FlowName                       { return "test" }
func (this *sshTestStoredSession) Id() session.Id                                { return this.id }
func (*sshTestStoredSession) Info(context.Context) (session.Info, error)         { return nil, nil }
func (*sshTestStoredSession) AuthorizationToken(context.Context) ([]byte, error) { return nil, nil }
func (this *sshTestStoredSession) EnvironmentToken(context.Context) ([]byte, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return append([]byte(nil), this.environmentToken...), nil
}
func (*sshTestStoredSession) HasPublicKey(context.Context, gossh.PublicKey) (bool, error) {
	return false, nil
}
func (*sshTestStoredSession) ConnectionInterceptor(context.Context) (session.ConnectionInterceptor, error) {
	return nil, nil
}
func (*sshTestStoredSession) SetAuthorizationToken(context.Context, []byte) error { return nil }
func (this *sshTestStoredSession) SetEnvironmentToken(_ context.Context, value []byte) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.environmentToken = append([]byte(nil), value...)
	this.environmentTokenWrites.Add(1)
	return nil
}
func (*sshTestStoredSession) AddPublicKey(context.Context, gossh.PublicKey) error    { return nil }
func (*sshTestStoredSession) DeletePublicKey(context.Context, gossh.PublicKey) error { return nil }
func (*sshTestStoredSession) NotifyLastAccess(context.Context, bnet.Remote, session.State) (session.State, error) {
	return session.StateUnchanged, nil
}
func (*sshTestStoredSession) Dispose(context.Context) (bool, error) { return false, nil }
func (this *sshTestStoredSession) String() string                   { return this.id.String() }

type sshTestAuthorization struct {
	session     session.Session
	environment sys.EnvVars
	kind        string
	policy      *authorization.AuthorizedKeyPolicy
}

func (*sshTestAuthorization) IsAuthorized() bool                     { return true }
func (this *sshTestAuthorization) EnvVars() sys.EnvVars              { return this.environment }
func (*sshTestAuthorization) Flow() configuration.FlowName           { return "test" }
func (*sshTestAuthorization) Remote() bnet.Remote                    { return sshTestRemote{} }
func (this *sshTestAuthorization) FindSession() session.Session      { return this.session }
func (*sshTestAuthorization) FindSessionsPublicKey() gossh.PublicKey { return nil }
func (*sshTestAuthorization) Dispose(context.Context) (bool, error)  { return false, nil }
func (this *sshTestAuthorization) AuthorizationKind() string         { return this.kind }
func (this *sshTestAuthorization) AuthorizedKeyPolicy() *authorization.AuthorizedKeyPolicy {
	return this.policy
}

var _ authorization.Authorization = (*sshTestAuthorization)(nil)

type sshTestTask struct {
	context              *sshTestContext
	connection           connection.Connection
	authorization        authorization.Authorization
	session              essh.Session
	taskType             TaskType
	environmentVariables configuration.EnvironmentVariables
	targetUser           string
}

func (this *sshTestTask) GetField(name string) (any, bool, error) {
	if name == "targetUser" {
		return this.targetUser, true, nil
	}
	return nil, false, nil
}

func (this *sshTestTask) Connection() connection.Connection          { return this.connection }
func (this *sshTestTask) Context() essh.Context                      { return this.context }
func (this *sshTestTask) Authorization() authorization.Authorization { return this.authorization }
func (this *sshTestTask) SshSession() essh.Session                   { return this.session }
func (this *sshTestTask) TaskType() TaskType                         { return this.taskType }
func (this *sshTestTask) EnvironmentVariables() configuration.EnvironmentVariables {
	return this.environmentVariables
}
func (*sshTestTask) StartPreparation(string, string, PreparationProgressAttributes) (PreparationProgress, error) {
	return nil, nil
}

type sshTestSession struct {
	context            *sshTestContext
	command            string
	originalCommand    string
	hasOriginalCommand bool
	environment        []string
	stdin              *bytes.Reader
	stdout             bytes.Buffer
	stderr             bytes.Buffer
	signals            chan<- essh.Signal
}

func newSshTestSession(ctx *sshTestContext, command string, stdin []byte) *sshTestSession {
	return &sshTestSession{context: ctx, command: command, environment: []string{"LAYER=client", "SSH_ORIGINAL_COMMAND=forged-by-client"}, stdin: bytes.NewReader(stdin)}
}

func (this *sshTestSession) Read(value []byte) (int, error)            { return this.stdin.Read(value) }
func (this *sshTestSession) Write(value []byte) (int, error)           { return this.stdout.Write(value) }
func (*sshTestSession) Close() error                                   { return nil }
func (*sshTestSession) CloseWrite() error                              { return nil }
func (*sshTestSession) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (this *sshTestSession) Stderr() io.ReadWriter                     { return &this.stderr }
func (*sshTestSession) User() string                                   { return "source-user" }
func (*sshTestSession) RemoteAddr() gonet.Addr                         { return sshTestAddress("remote") }
func (*sshTestSession) LocalAddr() gonet.Addr                          { return sshTestAddress("local") }
func (this *sshTestSession) Environ() []string                         { return append([]string(nil), this.environment...) }
func (*sshTestSession) Exit(int) error                                 { return nil }
func (this *sshTestSession) Command() []string {
	if this.command == "" {
		return nil
	}
	return []string{this.command}
}
func (this *sshTestSession) RawCommand() string { return this.command }
func (this *sshTestSession) OriginalCommand() (string, bool) {
	return this.originalCommand, this.hasOriginalCommand
}
func (*sshTestSession) Subsystem() string                         { return "" }
func (*sshTestSession) PublicKey() essh.PublicKey                 { return nil }
func (this *sshTestSession) Context() essh.Context                { return this.context }
func (*sshTestSession) Permissions() essh.Permissions             { return essh.Permissions{} }
func (*sshTestSession) Pty() (essh.Pty, <-chan essh.Window, bool) { return essh.Pty{}, nil, false }
func (this *sshTestSession) Signals(signals chan<- essh.Signal)   { this.signals = signals }
func (*sshTestSession) Break(chan<- bool)                         {}
