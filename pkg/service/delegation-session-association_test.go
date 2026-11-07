package service

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

func incomingAssociationDelegation(t *testing.T, authority gossh.Signer, origin, target string, pty bool) gossh.Signer {
	t.Helper()
	subject := newIncomingCertificateTestSigner(t)
	now := time.Now().UTC().Truncate(time.Second)
	cert := &gossh.Certificate{Key: subject.PublicKey(), Serial: uint64(time.Now().UnixNano()), CertType: gossh.UserCert, KeyId: "bifroest:source:" + uuid.NewString(), ValidPrincipals: []string{target}, ValidAfter: uint64(now.Add(-30 * time.Second).Unix()), ValidBefore: uint64(now.Add(10 * time.Minute).Unix()), Permissions: gossh.Permissions{CriticalOptions: map[string]string{authorization.BifroestDelegationCriticalOption: ""}, Extensions: map[string]string{}}}
	if pty {
		cert.Extensions["permit-pty"] = ""
	}
	evidence := &authorization.AuthorizationEvidence{Schema: authorization.AuthorizationEvidenceSchema, Origin: authorization.AuthorizationEvidenceOrigin{User: origin, Host: "203.0.113.1", AuthorizationKind: "simple"}}
	require.NoError(t, evidence.Append(authorization.AuthorizationEvidenceHop{CaFingerprint: gossh.FingerprintSHA256(authority.PublicKey()), SubjectKeyFingerprint: gossh.FingerprintSHA256(subject.PublicKey()), Serial: cert.Serial, KeyId: cert.KeyId, SessionId: uuid.NewString(), Flow: "source", AuthorizationKind: "simple", Audience: "restricted-key", TargetUser: target, IssuedAt: now, ValidAfter: now.Add(-30 * time.Second), ValidBefore: now.Add(10 * time.Minute), PtyAllowed: pty}))
	raw, err := authorization.EncodeAuthorizationEvidence(evidence)
	require.NoError(t, err)
	cert.Extensions[authorization.AuthorizationEvidenceExtension] = string(raw)
	require.NoError(t, cert.SignCert(rand.Reader, authority))
	signer, err := gossh.NewCertSigner(cert, subject)
	require.NoError(t, err)
	return signer
}

func TestRealDelegationLoginsShareAssociationWithoutSharingConnectionPolicy(t *testing.T) {
	authority := newIncomingCertificateTestSigner(t)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		bifroest := &configuration.AuthorizationBifroest{}
		require.NoError(t, bifroest.SetDefaults())
		bifroest.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey()))))
		conf.Flows[0].Authorization.V = bifroest
	})
	first, err := dialAuthorizedKeysTestServer(server, incomingAssociationDelegation(t, authority, "origin-alice", server.username, true))
	require.NoError(t, err)
	defer first.Close()
	one, err := first.NewSession()
	require.NoError(t, err)
	require.NoError(t, one.RequestPty("xterm", 24, 80, nil))
	require.NoError(t, one.Run("first"))
	var original session.Session
	require.NoError(t, server.service.sessions.FindAll(t.Context(), func(_ context.Context, candidate session.Session) (bool, error) {
		original = candidate
		return false, nil
	}, nil))
	require.NotNil(t, original)
	before, err := original.AuthorizationToken(t.Context())
	require.NoError(t, err)
	second, err := dialAuthorizedKeysTestServer(server, incomingAssociationDelegation(t, authority, "origin-alice", server.username, false))
	require.NoError(t, err)
	defer second.Close()
	two, err := second.NewSession()
	require.NoError(t, err)
	require.Error(t, two.RequestPty("xterm", 24, 80, nil))
	require.NoError(t, two.Run("second"))
	count := 0
	require.NoError(t, server.service.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Equal(t, 1, count)
	after, err := original.AuthorizationToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, before, after, "new certificate must not overwrite creation evidence")
	binding, err := session.AssociationOf(t.Context(), original)
	require.NoError(t, err)
	require.Equal(t, "origin-alice", binding.Subject)
	third, err := dialAuthorizedKeysTestServer(server, incomingAssociationDelegation(t, authority, "origin-bob", server.username, false))
	require.NoError(t, err)
	defer third.Close()
	count = 0
	require.NoError(t, server.service.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Equal(t, 2, count, "different attested origins must not share ownership")
}
