package https

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocumentPolicyOnlyAddsCanonicalServerNonce(t *testing.T) {
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 32))
	policy, err := DocumentPolicy(nonce)
	require.NoError(t, err)
	require.Contains(t, policy, "script-src 'self' 'nonce-"+nonce+"'")
	require.Contains(t, policy, "style-src 'self' 'nonce-"+nonce+"'")
	require.Contains(t, policy, "frame-ancestors 'none'")
	require.Contains(t, policy, "base-uri 'none'")
	require.NotContains(t, policy, "unsafe-inline")
	require.NotContains(t, policy, "unsafe-eval")
	for _, bad := range []string{"", strings.Repeat("A", 40), nonce + "\r\nInjected: value", nonce + "' unsafe-inline", base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		_, err := DocumentPolicy(bad)
		require.Error(t, err)
	}
}
