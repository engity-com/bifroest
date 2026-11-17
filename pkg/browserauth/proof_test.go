package browserauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func proofTestKey(t *testing.T) (*ecdsa.PrivateKey, PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key, PublicKey(base64.StdEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y)))
}

func proofTestContext() Context {
	return Context{Purpose: "resume", Origin: "https://app.example.org:8443", Slug: "Work", Flow: "work", SessionID: "opaque-session", BindingID: "opaque-binding", Revision: 1, Target: "target-digest"}
}

func proofTestSign(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}

func TestChallengeSignsExactDomainSeparatedContextAndIsSingleUse(t *testing.T) {
	private, public := proofTestKey(t)
	challenge, err := NewChallenge(public, proofTestContext())
	require.NoError(t, err)
	payload := challenge.Bytes()
	require.True(t, bytes.HasPrefix(payload, []byte("bifroest-browser-remember-v1\x00")))
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(payload[len("bifroest-browser-remember-v1\x00"):], &fields))
	require.Equal(t, `"https://app.example.org:8443"`, string(fields["origin"]))
	require.Equal(t, `"Work"`, string(fields["slug"]))
	require.Equal(t, `"opaque-session"`, string(fields["sessionId"]))
	require.Equal(t, `"opaque-binding"`, string(fields["bindingId"]))
	require.Equal(t, "1", string(fields["revision"]))
	require.NotEmpty(t, fields["nonce"])
	payload[0] = 'X'
	require.NotEqual(t, payload, challenge.Bytes(), "callers cannot mutate the stored challenge")
	signature := proofTestSign(t, private, challenge.Bytes())
	require.NoError(t, challenge.Verify(signature))
	require.ErrorIs(t, challenge.Verify(signature), ErrInvalidProof)
	other, err := NewChallenge(public, proofTestContext())
	require.NoError(t, err)
	require.NotEqual(t, other.Bytes(), challenge.Bytes())
	require.ErrorIs(t, other.Verify(signature), ErrInvalidProof, "same-key replay across a fresh nonce is rejected")
}

func TestChallengeFailureExpiryAndScopeChangesCannotReplay(t *testing.T) {
	private, public := proofTestKey(t)
	now := time.Now()
	for _, mode := range []string{"wrong key", "changed payload", "short", "long", "zeros", "expiry", "purpose", "origin", "slug", "flow", "session", "binding", "revision", "target"} {
		t.Run(mode, func(t *testing.T) {
			challenge, err := newChallenge(public, proofTestContext(), now)
			require.NoError(t, err)
			payload := challenge.Bytes()
			signature := proofTestSign(t, private, payload)
			switch mode {
			case "wrong key":
				other, _ := proofTestKey(t)
				signature = proofTestSign(t, other, payload)
			case "changed payload":
				payload[len(payload)-2] ^= 1
				signature = proofTestSign(t, private, payload)
			case "short":
				signature = signature[:63]
			case "long":
				signature = append(signature, 0)
			case "zeros":
				signature = make([]byte, 64)
			case "expiry":
				require.ErrorIs(t, challenge.verify(signature, now.Add(ChallengeLifetime)), ErrInvalidProof)
			default:
				scope := proofTestContext()
				switch mode {
				case "purpose":
					scope.Purpose = "revoke"
				case "origin":
					scope.Origin = "https://app.example.org"
				case "slug":
					scope.Slug = "work"
				case "flow":
					scope.Flow = "other"
				case "session":
					scope.SessionID = "other"
				case "binding":
					scope.BindingID = "other"
				case "revision":
					scope.Revision++
				case "target":
					scope.Target = "other"
				}
				other, err := newChallenge(public, scope, now)
				require.NoError(t, err)
				signature = proofTestSign(t, private, other.Bytes())
			}
			require.ErrorIs(t, challenge.verify(signature, now), ErrInvalidProof)
			require.ErrorIs(t, challenge.verify(proofTestSign(t, private, challenge.Bytes()), now), ErrInvalidProof, "failed proofs are consumed too")
		})
	}
}

func TestChallengeParallelVerificationHasExactlyOneWinner(t *testing.T) {
	private, public := proofTestKey(t)
	challenge, err := NewChallenge(public, proofTestContext())
	require.NoError(t, err)
	signature := proofTestSign(t, private, challenge.Bytes())
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			if challenge.Verify(signature) == nil {
				winners.Add(1)
			}
		}()
	}
	group.Wait()
	require.EqualValues(t, 1, winners.Load())
}

func TestPublicKeyParserAcceptsOnlyCanonicalUncompressedP256(t *testing.T) {
	_, public := proofTestKey(t)
	require.NotEmpty(t, public)
	parsed, err := public.Parse()
	require.NoError(t, err)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), parsed.X, parsed.Y)
	for _, raw := range []PublicKey{"", PublicKey(strings.Repeat("x", 100000)), public + "\n", PublicKey(strings.TrimSuffix(string(public), "=")), PublicKey(base64.StdEncoding.EncodeToString(compressed)), PublicKey(base64.StdEncoding.EncodeToString(make([]byte, 65))), PublicKey("-----BEGIN PRIVATE KEY-----")} {
		_, err := raw.Parse()
		require.ErrorIs(t, err, ErrInvalidProof)
	}
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		_, err = PublicKey(base64.StdEncoding.EncodeToString(elliptic.Marshal(curve, key.X, key.Y))).Parse()
		require.ErrorIs(t, err, ErrInvalidProof)
	}
}

func TestEnrollmentHasNoPreexistingBindingOrRevision(t *testing.T) {
	_, public := proofTestKey(t)
	scope := proofTestContext()
	scope.Purpose = "enroll"
	scope.BindingID = ""
	scope.Revision = 0
	_, err := NewChallenge(public, scope)
	require.NoError(t, err)
	scope.Revision = 1
	_, err = NewChallenge(public, scope)
	require.ErrorIs(t, err, ErrInvalidProof)
	var absent *Challenge
	require.ErrorIs(t, absent.Verify(make([]byte, 64)), ErrInvalidProof)
	// ECDSA's ASN.1 signature encoding must not accidentally become the protocol.
	key, public := proofTestKey(t)
	challenge, err := NewChallenge(public, proofTestContext())
	require.NoError(t, err)
	digest := sha256.Sum256(challenge.Bytes())
	asn1, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	require.ErrorIs(t, challenge.Verify(asn1), ErrInvalidProof)
}
