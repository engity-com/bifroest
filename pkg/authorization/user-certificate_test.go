package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func TestEvaluateGlobalUserCertificate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	authority := newUserCertificateTestSigner(t)
	subject := newUserCertificateTestSigner(t)
	certificate := newUserCertificateTestCertificate(t, authority, subject.PublicKey(), now)

	policy, accepted, err := evaluatePublicKeyCredential(certificate, "alice", bnet.Host{}, []ssh.PublicKey{authority.PublicKey()}, emptyAuthorizedKeySource, now)
	require.NoError(t, err)
	require.True(t, accepted)
	require.True(t, policy.PtyAllowed)
	require.False(t, policy.PortForwardingAllowed)
	require.False(t, policy.AgentForwardingAllowed)
}

func TestEvaluateGlobalUserCertificateRejectsInvalidCertificate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	authority := newUserCertificateTestSigner(t)
	otherAuthority := newUserCertificateTestSigner(t)
	subject := newUserCertificateTestSigner(t)

	for name, mutate := range map[string]func(*ssh.Certificate){
		"wrong-principal":  func(cert *ssh.Certificate) { cert.ValidPrincipals = []string{"bob"} },
		"no-principals":    func(cert *ssh.Certificate) { cert.ValidPrincipals = nil },
		"expired":          func(cert *ssh.Certificate) { cert.ValidBefore = uint64(now.Unix()) },
		"not-yet-valid":    func(cert *ssh.Certificate) { cert.ValidAfter = uint64(now.Add(time.Minute).Unix()) },
		"host-certificate": func(cert *ssh.Certificate) { cert.CertType = ssh.HostCert },
		"critical-option":  func(cert *ssh.Certificate) { cert.CriticalOptions["force-command"] = "id" },
		"unknown-critical": func(cert *ssh.Certificate) { cert.CriticalOptions["custom@example.org"] = "value" },
		"extension-value":  func(cert *ssh.Certificate) { cert.Extensions["permit-pty"] = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			certificate := newUserCertificateTestCertificateWithMutation(t, authority, subject.PublicKey(), now, mutate)
			_, accepted, err := evaluatePublicKeyCredential(certificate, "alice", bnet.Host{}, []ssh.PublicKey{authority.PublicKey()}, emptyAuthorizedKeySource, now)
			require.NoError(t, err)
			require.False(t, accepted)
		})
	}

	certificate := newUserCertificateTestCertificate(t, authority, subject.PublicKey(), now)
	_, accepted, err := evaluatePublicKeyCredential(certificate, "alice", bnet.Host{}, []ssh.PublicKey{otherAuthority.PublicKey()}, emptyAuthorizedKeySource, now)
	require.NoError(t, err)
	require.False(t, accepted)
}

func TestEvaluateGlobalUserCertificateRejectsInvalidSignature(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	authority := newUserCertificateTestSigner(t)
	certificate := newUserCertificateTestCertificate(t, authority, newUserCertificateTestSigner(t).PublicKey(), now)
	certificate.ValidBefore++

	_, accepted, err := evaluatePublicKeyCredential(certificate, "alice", bnet.Host{}, []ssh.PublicKey{authority.PublicKey()}, emptyAuthorizedKeySource, now)
	require.NoError(t, err)
	require.False(t, accepted)
}

func TestLoadTrustedUserCAsCreatesCombinedSnapshot(t *testing.T) {
	inline := newUserCertificateTestSigner(t).PublicKey()
	fromFile := newUserCertificateTestSigner(t).PublicKey()
	replacement := newUserCertificateTestSigner(t).PublicKey()
	filename := filepath.Join(t.TempDir(), "cas")
	require.NoError(t, os.WriteFile(filename, ssh.MarshalAuthorizedKey(fromFile), 0600))
	conf := configuration.UserCertificateAuthorityProperties{
		TrustedUserCAs:     crypto.PublicKeys(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(inline)))),
		TrustedUserCAsFile: crypto.PublicKeysFile(filename),
	}

	actual, err := loadTrustedUserCAs(&conf)
	require.NoError(t, err)
	require.Len(t, actual, 2)
	require.True(t, publicKeysEqual(inline, actual[0]))
	require.True(t, publicKeysEqual(fromFile, actual[1]))
	require.NoError(t, os.WriteFile(filename, ssh.MarshalAuthorizedKey(replacement), 0600))
	require.True(t, publicKeysEqual(fromFile, actual[1]))
}

func TestLoadTrustedUserCAsRejectsEmptyExplicitSource(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cas")
	require.NoError(t, os.WriteFile(filename, []byte("# empty\n"), 0600))
	_, err := loadTrustedUserCAs(&configuration.UserCertificateAuthorityProperties{TrustedUserCAsFile: crypto.PublicKeysFile(filename)})
	require.ErrorContains(t, err, "does not contain")
}

func TestEvaluateAuthorizedKeysCertificateAuthority(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	authority := newUserCertificateTestSigner(t)
	subject := newUserCertificateTestSigner(t)
	certificate := newUserCertificateTestCertificate(t, authority, subject.PublicKey(), now)
	source := oneAuthorizedKeySource(authority.PublicKey(), []crypto.AuthorizedKeyOption{
		{Type: crypto.AuthorizedKeyCertAuthority},
		{Type: crypto.AuthorizedKeyPrincipals, Value: "alice,automation"},
		{Type: crypto.AuthorizedKeyRestrict},
		{Type: crypto.AuthorizedKeyPty},
	})

	policy, accepted, err := evaluatePublicKeyCredential(certificate, "alice", bnet.Host{}, nil, source, now)
	require.NoError(t, err)
	require.True(t, accepted)
	require.True(t, policy.PtyAllowed)
	require.False(t, policy.PortForwardingAllowed)
	require.False(t, policy.AgentForwardingAllowed)
}

func TestCertificateCannotReenableAuthorizedKeyRestrictions(t *testing.T) {
	certificate := &ssh.Certificate{Permissions: ssh.Permissions{Extensions: map[string]string{
		"permit-pty":              "",
		"permit-port-forwarding":  "",
		"permit-agent-forwarding": "",
	}}}
	policy, err := authorizedKeyPolicyForCertificate(&AuthorizedKeyPolicy{}, certificate)
	require.NoError(t, err)
	require.False(t, policy.PtyAllowed)
	require.False(t, policy.PortForwardingAllowed)
	require.False(t, policy.AgentForwardingAllowed)
}

func TestEvaluateAuthorizedKeysCertificateAuthorityRestrictions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	authority := newUserCertificateTestSigner(t)
	subject := newUserCertificateTestSigner(t)
	certificate := newUserCertificateTestCertificate(t, authority, subject.PublicKey(), now)

	for name, test := range map[string]struct {
		key     ssh.PublicKey
		options []crypto.AuthorizedKeyOption
	}{
		"principal-mismatch": {authority.PublicKey(), []crypto.AuthorizedKeyOption{{Type: crypto.AuthorizedKeyCertAuthority}, {Type: crypto.AuthorizedKeyPrincipals, Value: "bob"}}},
		"ordinary-ca-key":    {authority.PublicKey(), nil},
		"subject-key":        {subject.PublicKey(), nil},
		"ca-as-direct-key":   {authority.PublicKey(), []crypto.AuthorizedKeyOption{{Type: crypto.AuthorizedKeyCertAuthority}}},
	} {
		t.Run(name, func(t *testing.T) {
			remote := ssh.PublicKey(certificate)
			if name == "ca-as-direct-key" {
				remote = authority.PublicKey()
			}
			_, accepted, err := evaluatePublicKeyCredential(remote, "alice", bnet.Host{}, nil, oneAuthorizedKeySource(test.key, test.options), now)
			require.NoError(t, err)
			require.False(t, accepted)
		})
	}
}

func TestEvaluateAuthorizedKeysRejectsPrincipalsWithoutCertificateAuthority(t *testing.T) {
	key := newUserCertificateTestSigner(t).PublicKey()
	_, _, err := evaluatePublicKeyCredential(key, "alice", bnet.Host{}, nil, oneAuthorizedKeySource(key, []crypto.AuthorizedKeyOption{{Type: crypto.AuthorizedKeyPrincipals, Value: "alice"}}), time.Now())
	require.ErrorContains(t, err, "requires")
}

func newUserCertificateTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	return signer
}

func newUserCertificateTestCertificate(t *testing.T, authority ssh.Signer, subject ssh.PublicKey, now time.Time) *ssh.Certificate {
	t.Helper()
	return newUserCertificateTestCertificateWithMutation(t, authority, subject, now, nil)
}

func newUserCertificateTestCertificateWithMutation(t *testing.T, authority ssh.Signer, subject ssh.PublicKey, now time.Time, mutate func(*ssh.Certificate)) *ssh.Certificate {
	t.Helper()
	certificate := &ssh.Certificate{
		Key:             subject,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-pty": "",
			},
		},
	}
	if mutate != nil {
		mutate(certificate)
	}
	require.NoError(t, certificate.SignCert(rand.Reader, authority))
	return certificate
}

func emptyAuthorizedKeySource(func(ssh.PublicKey, []crypto.AuthorizedKeyOption) (bool, error)) error {
	return nil
}

func oneAuthorizedKeySource(key ssh.PublicKey, options []crypto.AuthorizedKeyOption) authorizedKeySource {
	return func(consumer func(ssh.PublicKey, []crypto.AuthorizedKeyOption) (bool, error)) error {
		_, err := consumer(key, options)
		return err
	}
}
