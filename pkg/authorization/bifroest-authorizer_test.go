package authorization

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestBifroestAuthorizationTokenBindsIdentityAndCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	evidence := &AuthorizationEvidence{
		Schema: AuthorizationEvidenceSchema,
		Origin: AuthorizationEvidenceOrigin{User: "alice", Host: "203.0.113.1", AuthorizationKind: "simple"},
		Hops: []AuthorizationEvidenceHop{{
			CaFingerprint: ssh.FingerprintSHA256(newEvidenceTestSigner(t).PublicKey()), SubjectKeyFingerprint: ssh.FingerprintSHA256(newEvidenceTestSigner(t).PublicKey()),
			Serial: 1, KeyId: "bifroest:source:" + uuid.NewString(), SessionId: uuid.NewString(), Flow: "source", AuthorizationKind: "simple",
			Audience: "destination", TargetUser: "deploy", IssuedAt: now, ValidAfter: now.Add(-30 * time.Second), ValidBefore: now.Add(10 * time.Minute),
			PtyAllowed: true,
		}},
	}
	auth := &BifroestAuthorization{evidence: evidence, policy: &AuthorizedKeyPolicy{PtyAllowed: true}}
	first, err := encodeBifroestAuthorizationToken(auth)
	require.NoError(t, err)
	restored, err := decodeBifroestAuthorizationToken(first)
	require.NoError(t, err)
	require.Equal(t, evidence, &restored.Evidence)
	require.Equal(t, evidence.Policy(), restored.Policy)

	otherOrigin := evidence.Clone()
	otherOrigin.Origin.User = "bob"
	second, err := encodeBifroestAuthorizationToken(&BifroestAuthorization{evidence: otherOrigin, policy: auth.policy})
	require.NoError(t, err)
	require.False(t, bytes.Equal(first, second))

	otherCredential := evidence.Clone()
	otherCredential.Hops[0].KeyId = "bifroest:source:" + uuid.NewString()
	third, err := encodeBifroestAuthorizationToken(&BifroestAuthorization{evidence: otherCredential, policy: auth.policy})
	require.NoError(t, err)
	require.False(t, bytes.Equal(first, third))

	_, err = decodeBifroestAuthorizationToken(append(first, []byte("{}")...))
	require.ErrorContains(t, err, "trailing")
}
