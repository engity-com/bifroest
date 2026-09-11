package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	gonet "net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestSshCertificateFullStack(t *testing.T) {
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	authoritySigner, err := gossh.NewSignerFromKey(authorityKey)
	require.NoError(t, err)
	target := newSshCertificateE2ETarget(t, authoritySigner.PublicKey())

	directory := t.TempDir()
	authorityFile := filepath.Join(directory, "authority")
	subjectFile := filepath.Join(directory, "subject")
	privateKey, err := gossh.MarshalPrivateKey(authorityKey, "test user CA")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(authorityFile, pem.EncodeToMemory(privateKey), 0600))

	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		sshEnvironment := &configuration.EnvironmentSsh{}
		require.NoError(t, sshEnvironment.SetDefaults())
		sshEnvironment.Address = template.MustNewString(target.Address())
		sshEnvironment.User = template.MustNewString("target-user")
		sshEnvironment.KnownHosts = target.KnownHosts()
		certificate := &configuration.EnvironmentSshCertificate{}
		require.NoError(t, certificate.SetDefaults())
		certificate.IdentityFile = template.MustNewString(subjectFile)
		certificate.AuthorityIdentityFile = template.MustNewString(authorityFile)
		certificate.Validity = template.DurationOf(time.Hour)
		certificate.Extensions = configuration.EnvironmentSshCertificateExtensions{
			"permit-pty": template.MustNewString(""),
		}
		sshEnvironment.Certificate = certificate
		conf.Flows[0].Environment.V = sshEnvironment
	})

	firstOutput := runSshCertificateE2ECommand(t, server, "first")
	firstCertificate := target.NextCertificate(t)
	secondOutput := runSshCertificateE2ECommand(t, server, "second")
	secondCertificate := target.NextCertificate(t)

	firstParts := strings.SplitN(firstOutput, "|", 2)
	secondParts := strings.SplitN(secondOutput, "|", 2)
	require.Len(t, firstParts, 2)
	require.Len(t, secondParts, 2)
	require.Equal(t, []string{"first", firstParts[1]}, firstParts)
	require.Equal(t, []string{"second", secondParts[1]}, secondParts)
	require.NotEmpty(t, firstParts[1])
	require.Equal(t, firstParts[1], secondParts[1])
	require.Equal(t, firstCertificate.Marshal(), secondCertificate.Marshal())
	require.Equal(t, []string{"target-user"}, firstCertificate.ValidPrincipals)
	evidence, err := authorization.DecodeAuthorizationEvidence([]byte(firstCertificate.Extensions[authorization.AuthorizationEvidenceExtension]))
	require.NoError(t, err)
	require.Equal(t, firstParts[1], evidence.LastHop().SessionId)
	require.FileExists(t, subjectFile)
}

func runSshCertificateE2ECommand(t *testing.T, server *authorizedKeysTestServer, command string) string {
	t.Helper()
	client, err := server.dial()
	require.NoError(t, err)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	output, err := sshSession.Output(command)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	return string(output)
}

type sshCertificateE2ETarget struct {
	listener     gonet.Listener
	config       *gossh.ServerConfig
	hostKey      gossh.PublicKey
	certificates chan *gossh.Certificate
	closeOnce    sync.Once
	wait         sync.WaitGroup
}

func newSshCertificateE2ETarget(t *testing.T, authority gossh.PublicKey) *sshCertificateE2ETarget {
	t.Helper()
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := gossh.NewSignerFromKey(hostKey)
	require.NoError(t, err)
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	certificates := make(chan *gossh.Certificate, 2)
	checker := &gossh.CertChecker{IsUserAuthority: func(candidate gossh.PublicKey) bool {
		return gossh.FingerprintSHA256(candidate) == gossh.FingerprintSHA256(authority)
	}}
	config := &gossh.ServerConfig{PublicKeyCallback: func(metadata gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		certificate, ok := key.(*gossh.Certificate)
		if !ok {
			return nil, fmt.Errorf("target requires an SSH user certificate")
		}
		permissions, err := checker.Authenticate(metadata, certificate)
		if err != nil {
			return nil, err
		}
		certificates <- certificate
		return permissions, nil
	}}
	config.AddHostKey(hostSigner)
	target := &sshCertificateE2ETarget{listener: listener, config: config, hostKey: hostSigner.PublicKey(), certificates: certificates}
	target.wait.Add(1)
	go target.serve()
	t.Cleanup(target.Close)
	return target
}

func (this *sshCertificateE2ETarget) Address() string {
	return this.listener.Addr().String()
}

func (this *sshCertificateE2ETarget) KnownHosts() crypto.KnownHosts {
	return crypto.KnownHosts(knownhosts.Line([]string{this.Address()}, this.hostKey))
}

func (this *sshCertificateE2ETarget) NextCertificate(t *testing.T) *gossh.Certificate {
	t.Helper()
	select {
	case certificate := <-this.certificates:
		return certificate
	case <-time.After(5 * time.Second):
		t.Fatal("target did not receive an SSH user certificate")
		return nil
	}
}

func (this *sshCertificateE2ETarget) Close() {
	this.closeOnce.Do(func() {
		_ = this.listener.Close()
		this.wait.Wait()
	})
}

func (this *sshCertificateE2ETarget) serve() {
	defer this.wait.Done()
	for {
		connection, err := this.listener.Accept()
		if err != nil {
			return
		}
		this.wait.Add(1)
		go func() {
			defer this.wait.Done()
			this.serveConnection(connection)
		}()
	}
}

func (this *sshCertificateE2ETarget) serveConnection(raw gonet.Conn) {
	connection, channels, requests, err := gossh.NewServerConn(raw, this.config)
	if err != nil {
		_ = raw.Close()
		return
	}
	defer connection.Close()
	go gossh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(gossh.UnknownChannelType, "unsupported")
			continue
		}
		go serveSshCertificateE2ESession(channel)
	}
}

func serveSshCertificateE2ESession(channel gossh.NewChannel) {
	stream, requests, err := channel.Accept()
	if err != nil {
		return
	}
	defer stream.Close()
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
			if err := gossh.Unmarshal(request.Payload, &payload); err != nil {
				_ = request.Reply(false, nil)
				return
			}
			_ = request.Reply(true, nil)
			_, _ = io.WriteString(stream, payload.Command+"|"+environment[session.EnvName])
			_, _ = stream.SendRequest("exit-status", false, gossh.Marshal(&struct{ Status uint32 }{0}))
			return
		default:
			_ = request.Reply(false, nil)
		}
	}
}
