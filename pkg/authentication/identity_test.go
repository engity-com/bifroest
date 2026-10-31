package authentication

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentityValidation(t *testing.T) {
	for _, test := range []struct {
		name     string
		identity Identity
		valid    bool
	}{
		{"anonymous", Anonymous(), true},
		{"email", Identity{Principal: "alice@example.org", Issuer: "issuer", Subject: "subject"}, true},
		{"authenticated-anonymous-name", Identity{Principal: AnonymousPrincipal, Issuer: "issuer", Subject: "subject"}, true},
		{"empty", Identity{}, false},
		{"unverified-name", Identity{Principal: "alice"}, false},
		{"missing-subject", Identity{Principal: "alice", Issuer: "issuer"}, false},
		{"missing-issuer", Identity{Principal: "alice", Subject: "subject"}, false},
		{"control-character", Identity{Principal: "alice\n", Issuer: "issuer", Subject: "subject"}, false},
		{"invalid-utf8", Identity{Principal: string([]byte{255}), Issuer: "issuer", Subject: "subject"}, false},
		{"oversized", Identity{Principal: strings.Repeat("a", 1025), Issuer: "issuer", Subject: "subject"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.valid {
				require.NoError(t, test.identity.Validate())
			} else {
				require.Error(t, test.identity.Validate())
			}
		})
	}
}

func TestSubjectComparisonDoesNotUsePrincipal(t *testing.T) {
	first := Identity{Principal: "alice", Issuer: "issuer", Subject: "subject"}
	renamed := first
	renamed.Principal = "alice@example.org"
	require.True(t, first.SameSubject(renamed))
	other := first
	other.Issuer = "another-issuer"
	require.False(t, first.SameSubject(other))
	other = first
	other.Subject = "another-subject"
	require.False(t, first.SameSubject(other))
	require.False(t, Anonymous().SameSubject(Anonymous()))
}
