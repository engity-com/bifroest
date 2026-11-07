package authentication

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSessionCredentialHasNoSecretOrClientVerificationFields(t *testing.T) {
	for _, credential := range []SessionCredential{{Kind: "simple", Method: "password"}, {Kind: "oidc-device-auth", Method: "keyboard-interactive"}, {Kind: "local", Method: "public-key", PublicKey: base64.StdEncoding.EncodeToString([]byte("public-wire-parsed-by-authorizer"))}} {
		require.NoError(t, credential.Validate())
	}
	for _, credential := range []SessionCredential{{}, {Kind: "simple", Method: "browser-remember-me"}, {Kind: "simple", Method: "password", PublicKey: "private"}, {Kind: "simple", Method: "public-key"}, {Kind: "simple", Method: "public-key", PublicKey: "-----BEGIN PRIVATE KEY-----"}, {Kind: strings.Repeat("x", 129), Method: "password"}} {
		require.Error(t, credential.Validate())
	}
}
