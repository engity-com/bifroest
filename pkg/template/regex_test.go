package template

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegexFindAndReplaceForAuthorizationRequestNames(t *testing.T) {
	ctx := map[string]any{"remote": map[string]any{"user": "alice@remotehost"}}
	for source, expected := range map[string]string{
		`{{regexFind "^[^@]+" .remote.user}}`:                           "alice",
		`{{regexReplaceAll "@[^@]+$" .remote.user ""}}`:                 "alice",
		`{{regexReplaceAll "^([^@]+)@(.+)$" .remote.user "${1}"}}`:      "alice",
		`{{regexReplaceAll "^([^@]+)@(.+)$" .remote.user "${2}/${1}"}}`: "remotehost/alice",
		`{{mustRegexFind "^[^@]+" .remote.user}}`:                       "alice",
	} {
		t.Run(source, func(t *testing.T) {
			actual, err := MustNewString(source).Render(ctx)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
	for _, source := range []string{`{{mustRegexFind "[" .remote.user}}`, `{{mustRegexReplaceAll "[" .remote.user ""}}`} {
		_, err := MustNewString(source).Render(ctx)
		require.Error(t, err)
	}
	actual, err := MustNewString(`{{regexReplaceAll "@[^@]+$" .remote.user ""}}`).Render(map[string]any{"remote": map[string]any{"user": "alice@example.org@remotehost"}})
	require.NoError(t, err)
	require.Equal(t, "alice@example.org", actual, "strip only the final routing suffix, not an @ inside the account name")
}
