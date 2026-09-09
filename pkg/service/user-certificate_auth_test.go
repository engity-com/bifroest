package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestSimpleAuthorizationAcceptsGloballyTrustedUserCertificate(t *testing.T) {
	authority := newIncomingCertificateTestSigner(t)
	testEnvironment := &authorizedKeysTestEnvironment{}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", testEnvironment, func(conf *configuration.Configuration) {
		simple := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		simple.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey()))))
		simple.Entries[0].AuthorizedKeys = ""
	})
	certificateSigner := newIncomingCertificateSigner(t, authority, server.signer, server.username, map[string]string{"permit-pty": ""})

	client, err := dialAuthorizedKeysTestServer(server, certificateSigner)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.RequestPty("xterm", 24, 80, gossh.TerminalModes{}))
	require.NoError(t, sshSession.Run("true"))

	_, err = server.service.sessions.FindByPublicKey(t.Context(), certificateSigner.PublicKey(), &session.FindOpts{})
	require.ErrorIs(t, err, session.ErrNoSuchSession)
	_, err = server.service.sessions.FindByPublicKey(t.Context(), server.signer.PublicKey(), &session.FindOpts{})
	require.ErrorIs(t, err, session.ErrNoSuchSession)
}

func TestSimpleAuthorizationAppliesCertificateExtensions(t *testing.T) {
	authority := newIncomingCertificateTestSigner(t)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		simple := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		simple.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey()))))
	})
	certificateSigner := newIncomingCertificateSigner(t, authority, server.signer, server.username, nil)
	client, err := dialAuthorizedKeysTestServer(server, certificateSigner)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.RequestPty("xterm", 24, 80, gossh.TerminalModes{}))
}

func TestSimpleAuthorizationAcceptsTrustedUserCAsFileSnapshot(t *testing.T) {
	authority := newIncomingCertificateTestSigner(t)
	replacement := newIncomingCertificateTestSigner(t)
	filename := filepath.Join(t.TempDir(), "ca")
	require.NoError(t, os.WriteFile(filename, gossh.MarshalAuthorizedKey(authority.PublicKey()), 0600))
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		simple := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		simple.TrustedUserCAsFile = crypto.PublicKeysFile(filename)
	})
	require.NoError(t, os.WriteFile(filename, gossh.MarshalAuthorizedKey(replacement.PublicKey()), 0600))
	certificateSigner := newIncomingCertificateSigner(t, authority, server.signer, server.username, nil)

	client, err := dialAuthorizedKeysTestServer(server, certificateSigner)
	require.NoError(t, err)
	require.NoError(t, client.Close())
}

func TestSimpleAuthorizationAcceptsAuthorizedKeysCertificateAuthority(t *testing.T) {
	authority := newIncomingCertificateTestSigner(t)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		simple := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		simple.Entries[0].AuthorizedKeys = crypto.AuthorizedKeys(fmt.Sprintf(
			`cert-authority,principals="%s",restrict,pty %s`,
			serverUsername(conf), strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey()))),
		))
	})
	certificateSigner := newIncomingCertificateSigner(t, authority, server.signer, server.username, map[string]string{"permit-pty": "", "permit-port-forwarding": ""})

	client, err := dialAuthorizedKeysTestServer(server, certificateSigner)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.RequestPty("xterm", 24, 80, gossh.TerminalModes{}))

	directClient, err := dialAuthorizedKeysTestServer(server, authority)
	if directClient != nil {
		_ = directClient.Close()
	}
	require.Error(t, err)
}

func TestSimpleAuthorizationRejectsWrongCertificatePrincipal(t *testing.T) {
	authority := newIncomingCertificateTestSigner(t)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		simple := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		simple.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey()))))
	})
	certificateSigner := newIncomingCertificateSigner(t, authority, server.signer, "another-user", nil)

	client, err := dialAuthorizedKeysTestServer(server, certificateSigner)
	if client != nil {
		_ = client.Close()
	}
	require.Error(t, err)
}

func TestUserCertificateCreatesNoSessionBeforeProofAndIsRechecked(t *testing.T) {
	authority := newIncomingCertificateTestSigner(t)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		simple := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		simple.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey()))))
		simple.Entries[0].AuthorizedKeys = ""
	})
	expiresAt := time.Unix(time.Now().Unix()+3, 0)
	certificate := &gossh.Certificate{
		Key:             server.signer.PublicKey(),
		CertType:        gossh.UserCert,
		ValidPrincipals: []string{server.username},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(expiresAt.Unix()),
	}
	require.NoError(t, certificate.SignCert(rand.Reader, authority))
	certificateSigner, err := gossh.NewCertSigner(certificate, server.signer)
	require.NoError(t, err)
	blocking := &blockingIncomingCertificateSigner{
		Signer:      certificateSigner,
		signStarted: make(chan struct{}),
		releaseSign: make(chan struct{}),
	}
	dialResult := make(chan error, 1)
	go func() {
		client, err := dialAuthorizedKeysTestServer(server, blocking)
		if client != nil {
			_ = client.Close()
		}
		dialResult <- err
	}()

	select {
	case <-blocking.signStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not reach the signed public key request")
	}
	sessionCount := 0
	require.NoError(t, server.service.sessions.FindAll(t.Context(), func(_ context.Context, _ session.Session) (bool, error) {
		sessionCount++
		return true, nil
	}, nil))
	require.Zero(t, sessionCount)
	time.Sleep(time.Until(expiresAt) + 50*time.Millisecond)
	close(blocking.releaseSign)
	require.Error(t, <-dialResult)
}

func TestBifroestCertificateChain(t *testing.T) {
	for _, trustPath := range []string{"trusted-user-cas", "authorized-keys-cert-authority"} {
		t.Run(trustPath, func(t *testing.T) {
			testBifroestCertificateChain(t, trustPath)
		})
	}
}

func testBifroestCertificateChain(t *testing.T, trustPath string) {
	_, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	authority, err := gossh.NewSignerFromKey(authorityPrivate)
	require.NoError(t, err)
	targetEnvironment := &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		_, err := fmt.Fprintf(task.SshSession(), "bifroest-b|%s", task.SshSession().RawCommand())
		return 0, err
	}}
	target := newAuthorizedKeysTestServerWithConfiguration(t, "", targetEnvironment, func(conf *configuration.Configuration) {
		simple := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		plainAuthority := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey())))
		switch trustPath {
		case "trusted-user-cas":
			simple.TrustedUserCAs = crypto.PublicKeys(plainAuthority)
		case "authorized-keys-cert-authority":
			simple.Entries[0].AuthorizedKeys = crypto.AuthorizedKeys(`cert-authority,principals="` + simple.Entries[0].Name + `" ` + plainAuthority)
		default:
			t.Fatalf("unknown trust path %q", trustPath)
		}
	})

	directory := t.TempDir()
	authorityFile := filepath.Join(directory, "authority")
	subjectFile := filepath.Join(directory, "subject")
	privateKey, err := gossh.MarshalPrivateKey(authorityPrivate, "Bifroest chain test CA")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(authorityFile, pem.EncodeToMemory(privateKey), 0600))

	proxy := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		sshEnvironment := &configuration.EnvironmentSsh{}
		require.NoError(t, sshEnvironment.SetDefaults())
		sshEnvironment.Address = template.MustNewString(target.address)
		sshEnvironment.User = template.MustNewString(target.username)
		sshEnvironment.AcceptAllHostKeys = true
		certificate := &configuration.EnvironmentSshCertificate{}
		require.NoError(t, certificate.SetDefaults())
		certificate.IdentityFile = template.MustNewString(subjectFile)
		certificate.AuthorityIdentityFile = template.MustNewString(authorityFile)
		certificate.Validity = template.DurationOf(time.Hour)
		certificate.Extensions = configuration.EnvironmentSshCertificateExtensions{}
		sshEnvironment.Certificate = certificate
		conf.Flows[0].Environment.V = sshEnvironment
	})

	client := proxy.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	output, err := sshSession.Output("through-a")
	require.NoError(t, err)
	require.Equal(t, "bifroest-b|through-a", string(output))
}

func serverUsername(conf *configuration.Configuration) string {
	return conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Name
}

func newIncomingCertificateTestSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	return signer
}

func newIncomingCertificateSigner(t *testing.T, authority, subject gossh.Signer, principal string, extensions map[string]string) gossh.Signer {
	t.Helper()
	now := time.Now()
	certificate := &gossh.Certificate{
		Key:             subject.PublicKey(),
		CertType:        gossh.UserCert,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
		Permissions:     gossh.Permissions{Extensions: extensions},
	}
	require.NoError(t, certificate.SignCert(rand.Reader, authority))
	result, err := gossh.NewCertSigner(certificate, subject)
	require.NoError(t, err)
	return result
}

func dialAuthorizedKeysTestServer(server *authorizedKeysTestServer, signer gossh.Signer) (*gossh.Client, error) {
	return gossh.Dial("tcp", server.address, &gossh.ClientConfig{
		User:            server.username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // The server and key are test-local.
		Timeout:         5 * time.Second,
	})
}

type blockingIncomingCertificateSigner struct {
	gossh.Signer
	signStarted chan struct{}
	releaseSign chan struct{}
	signOnce    sync.Once
}

func (this *blockingIncomingCertificateSigner) Sign(random io.Reader, data []byte) (*gossh.Signature, error) {
	this.signOnce.Do(func() { close(this.signStarted) })
	<-this.releaseSign
	return this.Signer.Sign(random, data)
}
