package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOnlyVersionedBrowserAssetsAreImmutable(t *testing.T) {
	for _, name := range []string{"index-A1b2C3d4.js", "OidcLogin-A1b2C3d4.js", "index-bKgyieX_.css", "favicon-D9LofPsW.svg"} {
		require.True(t, webVersionedAsset.MatchString("/assets/"+name), name)
	}
	for _, name := range []string{"browser-key-worker.js", "browser-transfer-worker.js", "browser-evidence-worker.js", "go-wasm-exec.js", "browser-key.wasm", "third-party-licenses.txt"} {
		require.False(t, webVersionedAsset.MatchString("/assets/"+name), name)
	}
}
