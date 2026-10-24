package session

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
)

func associationTestTarget(t *testing.T, user string) Target {
	t.Helper()
	target, err := NewTarget("ssh", map[string]string{"address": "work.example.org:22", "user": user})
	require.NoError(t, err)
	return target
}

func associationTestIdentity() authentication.Identity {
	return authentication.Identity{Principal: "alice", Issuer: "https://issuer.example.org", Subject: "stable-subject"}
}

func TestSessionTargetEncodingIsCanonicalAndUnambiguous(t *testing.T) {
	first, err := NewTarget("ssh", map[string]string{"address": "work:22", "user": "alice"})
	require.NoError(t, err)
	second, err := NewTarget("ssh", map[string]string{"user": "alice", "address": "work:22"})
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.NoError(t, first.Validate())
	for _, fields := range []map[string]string{{"address": "other:22", "user": "alice"}, {"address": "work:22", "user": "bob"}, {"address": "work:22\x00user\x00alice", "user": ""}} {
		other, err := NewTarget("ssh", fields)
		require.NoError(t, err)
		require.NotEqual(t, first, other)
	}
	_, err = NewTarget("ssh", nil)
	require.Error(t, err)
	_, err = NewTarget("", map[string]string{"user": "alice"})
	require.Error(t, err)
	_, err = NewTarget("ssh", map[string]string{"user": strings.Repeat("x", 16385)})
	require.Error(t, err)
	large := map[string]string{}
	for i := 0; i < 32; i++ {
		large[strings.Repeat("x", i+1)] = strings.Repeat("v", 16384)
	}
	_, err = NewTarget("ssh", large)
	require.Error(t, err)
	require.Error(t, Target(strings.ToUpper(string(first))).Validate())
	require.Error(t, Target("known-session-id").Validate())
}

func TestAssociationUsesStableSubjectNotPrincipalOrAnonymousLabel(t *testing.T) {
	identity := associationTestIdentity()
	association, err := NewAssociation(identity, associationTestTarget(t, "work"))
	require.NoError(t, err)
	identity.Principal = "mapped-display-name"
	require.True(t, association.SameSubject(identity))
	identity.Subject = "other-subject"
	require.False(t, association.SameSubject(identity))
	identity = associationTestIdentity()
	identity.Issuer = "https://other.example.org"
	require.False(t, association.SameSubject(identity))
	_, err = NewAssociation(authentication.Anonymous(), association.Target)
	require.ErrorIs(t, err, ErrAnonymousAssociation)
	require.False(t, association.SameSubject(authentication.Anonymous()))
	_, err = NewAssociation(associationTestIdentity(), Target("client-target"))
	require.ErrorIs(t, err, ErrInvalidAssociation)
}

func TestAssociationDecoderRejectsUnknownDuplicateMalformedAndTrailingState(t *testing.T) {
	association, err := NewAssociation(associationTestIdentity(), associationTestTarget(t, "work"))
	require.NoError(t, err)
	raw, err := json.Marshal(association)
	require.NoError(t, err)
	parsed, err := decodeAssociation(raw)
	require.NoError(t, err)
	require.Equal(t, association, *parsed)
	for _, data := range []string{
		`null`, `[]`, `{}`, string(raw) + `{}`, string(raw) + ` garbage`,
		strings.Replace(string(raw), `"schema":`, `"unknown":`, 1),
		strings.Replace(string(raw), AssociationSchema, "unknown-schema", 1),
		strings.Replace(string(raw), `"subject":"stable-subject"`, `"subject":null`, 1),
		strings.Replace(string(raw), `"subject":"stable-subject"`, `"subject":3`, 1),
		strings.Replace(string(raw), `"subject":"stable-subject"`, `"subject":"secret-not-for-logs","subject":"stable-subject"`, 1),
		strings.Replace(string(raw), `stable-subject`, "invalid-\xff-UTF8", 1),
		strings.Replace(string(raw), `stable-subject`, `invalid-\ud800-high-surrogate`, 1),
		strings.Replace(string(raw), `stable-subject`, `invalid-\udc00-low-surrogate`, 1),
	} {
		_, err := decodeAssociation([]byte(data))
		require.ErrorIs(t, err, ErrInvalidAssociation)
		require.NotContains(t, err.Error(), "secret-not-for-logs")
	}
	_, err = AssociationOf(context.Background(), nil)
	require.ErrorIs(t, err, ErrAssociationUnavailable)
	unicodeState := strings.Replace(string(raw), `stable-subject`, `valid-\ud83d\ude00`, 1)
	valid, err := decodeAssociation([]byte(unicodeState))
	require.NoError(t, err)
	require.Equal(t, "valid-😀", valid.Subject)
}
