package service

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type connectionTemplateSshContext struct {
	essh.Context
	conn *connection
}

func (*connectionTemplateSshContext) User() string { return "foo@bar" }
func (*connectionTemplateSshContext) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.9"), Port: 54321}
}
func (c *connectionTemplateSshContext) Value(key any) any {
	if key == connectionCtxKey {
		return c.conn
	}
	return nil
}

func TestConnectionMetadataIsInheritedBySshRenderingContexts(t *testing.T) {
	id, err := bconn.NewId()
	require.NoError(t, err)
	ctx := &connectionTemplateSshContext{}
	conn := &connection{id: id, context: ctx}
	ctx.conn = conn
	base := environmentContext{connection: conn}
	request := authorizeRequest{connection: conn}
	prepared := &environmentRequestPreparationProgress{environmentRequest: &environmentRequest{environmentContext: base}}
	notification := newRememberMeNotificationContext(ctx, authorization.Forbidden(conn.Remote()), false, nil)
	contexts := []any{&request, &passwordAuthorizeRequest{authorizeRequest: request}, &publicKeyAuthorizeRequest{authorizeRequest: request}, &interactiveAuthorizeRequest{authorizeRequest: request}, &base, &environmentRequest{environmentContext: base}, &environmentTask{environmentContext: base}, &terminalEnvironmentTask{environmentContext: base}, prepared, &principalMappingContext{environmentContext: &base}, &connectionContext{Context: ctx, connection: conn}, notification, sessionRecordingNoticeContext{connection: conn}}
	for _, current := range contexts {
		actual, err := template.MustNewString(`{{.connection.id}}|{{.connection.transport}}|{{.connection.remote.user}}|{{if .connection.http}}unexpected{{else}}ssh-only{{end}}`).Render(current)
		require.NoError(t, err, "context %T", current)
		require.Equal(t, id.String()+"|ssh|foo@bar|ssh-only", actual)
	}
	legacy, err := template.MustNewString(`{{.remote.user}}`).Render(&connectionContext{Context: ctx, connection: conn})
	require.NoError(t, err)
	require.Equal(t, "foo@bar", legacy)
}

func TestHttpConnectionMetadataKeepsEachLogicalSelectionAcrossEnvironmentContexts(t *testing.T) {
	var first any
	for _, slug := range []string{"Docker", "Other"} {
		r := httptest.NewRequest("POST", "https://APP.EXAMPLE.ORG:8443/", nil)
		r.RemoteAddr = "192.0.2.9:54321"
		r.Header.Set("X-Forwarded-Proto", "ssh")
		r.Header.Set("X-Forwarded-Host", "must-not-be-used.invalid")
		scope, err := requestWebScope(r, slug)
		require.NoError(t, err)
		conn, err := newWebLoginConnection(t.Context(), r, scope, "foo@bar")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, conn.Close()) })
		base := environmentContext{connection: conn}
		contexts := []any{&authorizeRequest{connection: conn}, &base, &terminalEnvironmentRequest{environmentContext: base}, &terminalEnvironmentTask{environmentContext: base}, &principalMappingContext{environmentContext: &base}, &environmentRequestPreparationProgress{environmentRequest: &environmentRequest{environmentContext: base}}, sessionRecordingNoticeContext{connection: conn}}
		for _, current := range contexts {
			actual, err := template.MustNewString(`{{.connection.transport}}|{{.connection.http.host}}|{{.connection.http.slug}}|{{.connection.remote.user}}`).Render(current)
			require.NoError(t, err, "context %T", current)
			require.Equal(t, "http|app.example.org|"+slug+"|foo@bar", actual)
		}
		if first == nil {
			first = &base
		}
	}
	actual, err := template.MustNewString(`{{.connection.http.slug}}`).Render(first)
	require.NoError(t, err)
	require.Equal(t, "Docker", actual, "later requests cannot overwrite another logical selection on the same peer socket")
}

func TestConnectionMetadataRemainsAvailableDuringTargetAndSessionCompatibility(t *testing.T) {
	r := httptest.NewRequest("POST", "https://app.example.org/", nil)
	r.RemoteAddr = "192.0.2.9:54321"
	conn, err := newWebLoginConnection(t.Context(), r, webScope{Origin: "https://app.example.org", Slug: "Docker"}, "foo")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	base := &environmentContext{connection: conn}
	for _, current := range []any{&sessionCompatibilityEnvironmentContext{environmentContext: *base}, &associationCandidateContext{associationBaseContext: base, ctx: context.Background()}, newAssociationTargetContext(t.Context(), base, session.Reference{})} {
		actual, err := template.MustNewString(`{{.connection.transport}}|{{.connection.http.slug}}`).Render(current)
		require.NoError(t, err)
		require.Equal(t, "http|Docker", actual)
	}
	var _ environment.Context = base
}
