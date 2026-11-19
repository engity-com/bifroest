package authorization

import (
	"context"
	"fmt"
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

type oidcLoginMessageRequest struct{ InteractiveRequest }

func (oidcLoginMessageRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "remote":
		return map[string]string{"user": "alice"}, true, nil
	case "connection":
		return map[string]string{"transport": "ssh"}, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func TestOidcCodeRequestPreservesLoginMessageContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	parent := oidcLoginMessageRequest{}
	bounded := &oidcCodeRequest{InteractiveRequest: parent, ctx: ctx}
	for _, req := range []Request{parent, bounded} {
		message, err := RenderOidcSshLoginMessage(req, template.MustNewString(`Hello {{.remote.user}}/{{.connection.transport}}, code {{.code}}: {{.url}}`), "https://gateway.example/login/#start/ticket", "9D", true)
		require.NoError(t, err)
		require.Equal(t, "Hello alice/ssh, code 9D: https://gateway.example/login/#start/ticket", message)
	}
	require.Same(t, ctx, bounded.Context(), "forwarding template fields must not replace the bounded context")
	cancel()
	require.ErrorIs(t, bounded.Context().Err(), context.Canceled)
}

func TestOidcCodeRequestLoginMessageUnknownFieldsFailClosed(t *testing.T) {
	for _, parent := range []InteractiveRequest{nil, oidcLoginMessageRequest{}} {
		req := &oidcCodeRequest{InteractiveRequest: parent, ctx: t.Context()}
		_, err := RenderOidcSshLoginMessage(req, template.MustNewString(`{{.unknownPrivateField}}`), "https://gateway.example/login/#start/DO-NOT-LEAK-TICKET", "DO-NOT-LEAK-CODE", true)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "DO-NOT-LEAK")
	}
}
