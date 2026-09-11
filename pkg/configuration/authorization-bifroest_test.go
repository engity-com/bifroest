package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestAuthorizationBifroestConfiguration(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	plainKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	var authorization Authorization
	require.NoError(t, yaml.Unmarshal([]byte("type: bifroest\ntrustedUserCAs: "+plainKey+"\naudiences: [production, replacement]\n"), &authorization))
	actual, ok := authorization.V.(*AuthorizationBifroest)
	require.True(t, ok)
	require.Equal(t, BifroestAudiences{"production", "replacement"}, actual.Audiences)
	require.Equal(t, 15*time.Minute, actual.MaxCertificateValidity.Native())
	require.Equal(t, crypto.PublicKeys(plainKey), actual.TrustedUserCAs)

	roundtrip, err := yaml.Marshal(&authorization)
	require.NoError(t, err)
	var restored Authorization
	require.NoError(t, yaml.Unmarshal(roundtrip, &restored))
	require.True(t, authorization.IsEqualTo(restored))
}

func TestAuthorizationBifroestRejectsInvalidConfiguration(t *testing.T) {
	for _, plain := range []string{
		"type: bifroest\n",
		"type: bifroest\ntrustedUserCAs: invalid\n",
		"type: bifroest\ntrustedUserCAs: ssh-ed25519 AAAA\naudiences: ['']\n",
		"type: bifroest\ntrustedUserCAs: ssh-ed25519 AAAA\nmaxCertificateValidity: 0s\n",
	} {
		var authorization Authorization
		require.Error(t, yaml.Unmarshal([]byte(plain), &authorization))
	}
}

func TestAuthorizationBifroestRejectsExplicitlyEmptyAudiences(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	plainKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	var absent Authorization
	require.NoError(t, yaml.Unmarshal([]byte("type: bifroest\ntrustedUserCAs: "+plainKey+"\n"), &absent))
	require.Nil(t, absent.V.(*AuthorizationBifroest).Audiences)
	var empty Authorization
	require.Error(t, yaml.Unmarshal([]byte("type: bifroest\ntrustedUserCAs: "+plainKey+"\naudiences: []\n"), &empty))
}
