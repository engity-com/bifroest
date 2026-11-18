package authorization

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestOidcSshLoginMessageIsConciseAndCustomizable(t *testing.T) {
	message, err := RenderOidcSshLoginMessage(nil, template.String{}, "https://gateway.example/login/#start/ticket", "9D", true)
	require.NoError(t, err)
	require.Equal(t, `Open the following URL in your browser and provide the code "9D" to login: https://gateway.example/login/#start/ticket`, message)
	require.NotContains(t, message, "\n")
	message, err = RenderOidcSshLoginMessage(nil, template.String{}, "https://idp.example/verify?code=ABCD", "ABCD", false)
	require.NoError(t, err)
	require.Equal(t, "Open the following URL in your browser to login: https://idp.example/verify?code=ABCD", message)
	message, err = RenderOidcSshLoginMessage(nil, template.MustNewString(`Code {{.code}}: {{.url}} ({{.codeRequired}})`), "https://idp.example/verify", "ABCD", true)
	require.NoError(t, err)
	require.Equal(t, "Code ABCD: https://idp.example/verify (true)", message)
	_, err = RenderOidcSshLoginMessage(nil, template.MustNewString(strings.Repeat("x", 8193)), "https://idp.example", "ABCD", true)
	require.Error(t, err)
	_, err = RenderOidcSshLoginMessage(nil, template.MustNewString(`{{.unknownPrivateField}}`), "https://idp.example", "DO-NOT-LEAK", true)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "DO-NOT-LEAK")
}
