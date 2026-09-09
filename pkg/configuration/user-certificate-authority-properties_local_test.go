//go:build unix

package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func TestLocalTrustedUserCAsConfiguration(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	var authorization Authorization
	require.NoError(t, yaml.Unmarshal([]byte("type: local\ntrustedUserCAs: |\n  "+publicKey+"\nauthorizedKeys: [/tmp/authorized_keys]\npamService: test\n"), &authorization))
	actual := authorization.V.(*AuthorizationLocal)
	require.Equal(t, publicKey, string(actual.TrustedUserCAs))
	require.Len(t, actual.AuthorizedKeys, 1)

	roundtrip, err := yaml.Marshal(actual)
	require.NoError(t, err)
	var restored AuthorizationLocal
	require.NoError(t, yaml.Unmarshal(roundtrip, &restored))
	require.True(t, actual.IsEqualTo(restored))
}
