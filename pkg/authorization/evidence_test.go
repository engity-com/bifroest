package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestAuthorizationEvidenceRoundtripAndCertificateValidation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	authority := newEvidenceTestSigner(t)
	subject := newEvidenceTestSigner(t)
	certificate := &ssh.Certificate{
		Key:             subject.PublicKey(),
		Serial:          42,
		CertType:        ssh.UserCert,
		KeyId:           "bifroest:source:" + uuid.NewString(),
		ValidPrincipals: []string{"deploy"},
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()),
		ValidBefore:     uint64(now.Add(10 * time.Minute).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{BifroestDelegationCriticalOption: ""},
			Extensions:      map[string]string{"permit-pty": ""},
		},
	}
	evidence := &AuthorizationEvidence{
		Schema: AuthorizationEvidenceSchema,
		Origin: AuthorizationEvidenceOrigin{User: "alice", Host: "203.0.113.1", AuthorizationKind: "simple"},
	}
	require.NoError(t, evidence.Append(AuthorizationEvidenceHop{
		CaFingerprint:         ssh.FingerprintSHA256(authority.PublicKey()),
		SubjectKeyFingerprint: ssh.FingerprintSHA256(subject.PublicKey()),
		Serial:                certificate.Serial,
		KeyId:                 certificate.KeyId,
		SessionId:             uuid.NewString(),
		Flow:                  "source",
		AuthorizationKind:     "simple",
		Audience:              "destination",
		TargetUser:            "deploy",
		IssuedAt:              now,
		ValidAfter:            now.Add(-30 * time.Second),
		ValidBefore:           now.Add(10 * time.Minute),
		PtyAllowed:            true,
	}))
	raw, err := EncodeAuthorizationEvidence(evidence)
	require.NoError(t, err)
	certificate.Extensions[AuthorizationEvidenceExtension] = string(raw)
	require.NoError(t, certificate.SignCert(rand.Reader, authority))

	decoded, err := DecodeAuthorizationEvidence(raw)
	require.NoError(t, err)
	require.Equal(t, evidence, decoded)
	policy, err := ValidateBifroestDelegationEvidence(decoded, certificate, "deploy", []string{"destination"}, 15*time.Minute, now)
	require.NoError(t, err)
	require.True(t, policy.PtyAllowed)
	require.False(t, policy.PortForwardingAllowed)
}

func TestAuthorizationEvidenceStrictDecoding(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate":  `{"schema":"bifroest.authorization-evidence/v1","schema":"bifroest.authorization-evidence/v1"}`,
		"unknown":    `{"schema":"bifroest.authorization-evidence/v1","unknown":true}`,
		"suffix":     `{}` + `{}`,
		"whitespace": ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeAuthorizationEvidence([]byte(raw))
			require.Error(t, err)
		})
	}
	_, err := DecodeAuthorizationEvidence([]byte(strings.Repeat("x", MaxAuthorizationEvidenceSize+1)))
	require.ErrorContains(t, err, "exceeds")
}

func TestAuthorizationEvidenceRejectsCapabilityExpansionAndCycles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := newEvidenceTestSigner(t)
	second := newEvidenceTestSigner(t)
	base := AuthorizationEvidenceHop{
		CaFingerprint: ssh.FingerprintSHA256(first.PublicKey()), SubjectKeyFingerprint: ssh.FingerprintSHA256(second.PublicKey()), Serial: 1,
		KeyId: "one", SessionId: uuid.NewString(), Flow: "one", AuthorizationKind: "simple",
		Audience: "two", TargetUser: "deploy", IssuedAt: now, ValidAfter: now.Add(-time.Second), ValidBefore: now.Add(time.Minute),
	}
	evidence := &AuthorizationEvidence{Schema: AuthorizationEvidenceSchema, Origin: AuthorizationEvidenceOrigin{User: "alice", Host: "host", AuthorizationKind: "simple"}}
	require.NoError(t, evidence.Append(base))
	expanded := base
	expanded.SubjectKeyFingerprint = ssh.FingerprintSHA256(newEvidenceTestSigner(t).PublicKey())
	expanded.Serial = 2
	expanded.KeyId = "two"
	expanded.SessionId = uuid.NewString()
	expanded.Flow = "two"
	expanded.AuthorizationKind = "bifroest"
	expanded.PtyAllowed = true
	require.ErrorContains(t, evidence.Append(expanded), "extends previous capabilities")
	cycled := base
	cycled.Serial = 3
	cycled.KeyId = "three"
	cycled.SessionId = uuid.NewString()
	cycled.Flow = "three"
	require.ErrorContains(t, evidence.Append(cycled), "duplicates")
	invalid := evidence.Clone()
	invalid.Hops[0].SessionId = uuid.Nil.String()
	require.ErrorContains(t, invalid.Validate(), "sessionId")
	invalid = evidence.Clone()
	invalid.Hops[0].CaFingerprint = "SHA256:not-a-fingerprint"
	require.ErrorContains(t, invalid.Validate(), "caFingerprint")
	invalid = evidence.Clone()
	invalid.Hops[0].SubjectKeyFingerprint = nonCanonicalEvidenceTestFingerprint(t, invalid.Hops[0].SubjectKeyFingerprint)
	require.ErrorContains(t, invalid.Validate(), "subjectKeyFingerprint")
	extendedValidAfter := base
	extendedValidAfter.SubjectKeyFingerprint = ssh.FingerprintSHA256(newEvidenceTestSigner(t).PublicKey())
	extendedValidAfter.Serial = 4
	extendedValidAfter.KeyId = "four"
	extendedValidAfter.SessionId = uuid.NewString()
	extendedValidAfter.Flow = "four"
	extendedValidAfter.AuthorizationKind = "bifroest"
	extendedValidAfter.ValidAfter = base.ValidAfter.Add(-time.Second)
	require.ErrorContains(t, evidence.Append(extendedValidAfter), "valid-after")
}

func nonCanonicalEvidenceTestFingerprint(t *testing.T, fingerprint string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	encoded := strings.TrimPrefix(fingerprint, "SHA256:")
	require.Len(t, encoded, 43)
	last := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	require.GreaterOrEqual(t, last, 0)
	alternative := alphabet[(last&^3)|1]
	nonCanonical := encoded[:len(encoded)-1] + string(alternative)
	canonicalRaw, err := base64.RawStdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	nonCanonicalRaw, err := base64.RawStdEncoding.DecodeString(nonCanonical)
	require.NoError(t, err)
	require.Equal(t, canonicalRaw, nonCanonicalRaw)
	return "SHA256:" + nonCanonical
}

func TestEvaluateBifroestUserCertificateRejectsInvalidDelegations(t *testing.T) {
	for _, scenario := range []string{
		"missing-marker", "missing-evidence", "wrong-audience", "wrong-ca", "wrong-principal",
		"inconsistent-hop", "unauthenticated-origin", "too-long", "expired", "not-yet-valid",
	} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			authority := newEvidenceTestSigner(t)
			subject := newEvidenceTestSigner(t)
			username := "deploy"
			certificate := &ssh.Certificate{
				Key: subject.PublicKey(), Serial: 42, CertType: ssh.UserCert, KeyId: "bifroest:source:" + uuid.NewString(),
				ValidPrincipals: []string{username}, ValidAfter: uint64(now.Add(-30 * time.Second).Unix()), ValidBefore: uint64(now.Add(10 * time.Minute).Unix()),
				Permissions: ssh.Permissions{
					CriticalOptions: map[string]string{BifroestDelegationCriticalOption: ""},
					Extensions:      map[string]string{"permit-pty": ""},
				},
			}
			evidence := &AuthorizationEvidence{
				Schema: AuthorizationEvidenceSchema,
				Origin: AuthorizationEvidenceOrigin{User: "alice", Host: "203.0.113.1", AuthorizationKind: "simple"},
				Hops: []AuthorizationEvidenceHop{{
					CaFingerprint: ssh.FingerprintSHA256(authority.PublicKey()), SubjectKeyFingerprint: ssh.FingerprintSHA256(subject.PublicKey()),
					Serial: certificate.Serial, KeyId: certificate.KeyId, SessionId: uuid.NewString(), Flow: "source", AuthorizationKind: "simple",
					Audience: "destination", TargetUser: username, IssuedAt: now,
					ValidAfter: now.Add(-30 * time.Second), ValidBefore: now.Add(10 * time.Minute), PtyAllowed: true,
				}},
			}
			trusted := []ssh.PublicKey{authority.PublicKey()}
			includeEvidence := true
			switch scenario {
			case "missing-marker":
				delete(certificate.CriticalOptions, BifroestDelegationCriticalOption)
			case "missing-evidence":
				includeEvidence = false
			case "wrong-audience":
				evidence.Hops[0].Audience = "another-destination"
			case "wrong-ca":
				trusted = []ssh.PublicKey{newEvidenceTestSigner(t).PublicKey()}
			case "wrong-principal":
				username = "another-user"
			case "inconsistent-hop":
				evidence.Hops[0].Serial++
			case "unauthenticated-origin":
				evidence.Origin.AuthorizationKind = "none"
				evidence.Hops[0].AuthorizationKind = "none"
			case "too-long":
				certificate.ValidBefore = uint64(now.Add(16 * time.Minute).Unix())
				evidence.Hops[0].ValidBefore = now.Add(16 * time.Minute)
			case "expired":
				certificate.ValidAfter = uint64(now.Add(-2 * time.Minute).Unix())
				certificate.ValidBefore = uint64(now.Add(-time.Minute).Unix())
				evidence.Hops[0].IssuedAt = now.Add(-90 * time.Second)
				evidence.Hops[0].ValidAfter = now.Add(-2 * time.Minute)
				evidence.Hops[0].ValidBefore = now.Add(-time.Minute)
			case "not-yet-valid":
				certificate.ValidAfter = uint64(now.Add(time.Minute).Unix())
				certificate.ValidBefore = uint64(now.Add(2 * time.Minute).Unix())
				evidence.Hops[0].IssuedAt = now.Add(90 * time.Second)
				evidence.Hops[0].ValidAfter = now.Add(time.Minute)
				evidence.Hops[0].ValidBefore = now.Add(2 * time.Minute)
			}
			if includeEvidence {
				raw, err := EncodeAuthorizationEvidence(evidence)
				require.NoError(t, err)
				certificate.Extensions[AuthorizationEvidenceExtension] = string(raw)
			}
			require.NoError(t, certificate.SignCert(rand.Reader, authority))

			actualEvidence, policy, accepted, _ := evaluateBifroestUserCertificate(
				certificate, username, trusted, []string{"destination"}, 15*time.Minute, now,
			)
			require.False(t, accepted)
			require.Nil(t, actualEvidence)
			require.Nil(t, policy)
		})
	}
}

func newEvidenceTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	return signer
}
