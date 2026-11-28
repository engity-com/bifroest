package configuration

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReloadAccessComparisonExcludesOnlyKnownPresentation(t *testing.T) {
	source := `flows:
  - name: work
    title: Before
    authorization: {type: oidcDeviceAuth, issuer: "https://issuer.example", clientId: client, clientSecret: secret, ssh: {loginMessage: Before}}
    environment: {type: dummy, banner: Before}
`
	before := snapshotTestLoad(t, source)
	after := snapshotTestLoad(t, strings.ReplaceAll(source, "Before", "After"))
	require.True(t, before.ChangesTo(after).RuntimeChanged())
	require.False(t, before.AccessChangesTo(after).RuntimeChanged())
	key := bytes.Repeat([]byte{7}, 32)
	left, err := before.RuntimeDigests(key)
	require.NoError(t, err)
	right, err := after.RuntimeDigests(key)
	require.NoError(t, err)
	require.Equal(t, left, right, "cosmetic changes must not invalidate restart ownership")
	require.Equal(t, "Before", before.Configuration().Flows[0].Title)
	for _, changed := range []string{
		strings.Replace(source, "clientSecret: secret", "clientSecret: changed", 1),
		strings.Replace(source, "banner: Before", "banner: After, exitCode: 17", 1),
		strings.Replace(source, "title: Before", "title: After\n    ssh: {enabled: false}", 1),
	} {
		require.True(t, before.AccessChangesTo(snapshotTestLoad(t, changed)).RuntimeChanged())
	}
}
