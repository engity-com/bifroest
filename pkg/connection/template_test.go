package connection_test

import (
	"context"
	"testing"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/connection"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/template"
)

type metadataConnection struct {
	id   connection.Id
	peer *metadataPeer
}

func (c *metadataConnection) Id() connection.Id   { return c.id }
func (c *metadataConnection) Remote() bnet.Remote { return c.peer }
func (*metadataConnection) Logger() log.Logger    { panic("templates must not access a logger") }
func (*metadataConnection) Close() error          { panic("templates must not control a live connection") }
func (*metadataConnection) GetField(string) (any, bool, error) {
	return "PRIVATE-CONNECTION-SENTINEL", true, nil
}

type metadataPeer struct {
	user string
	host bnet.Host
}

func (p *metadataPeer) User() string    { return p.user }
func (p *metadataPeer) Host() bnet.Host { return p.host }
func (p *metadataPeer) String() string  { return p.user + "@" + p.host.String() }
func (*metadataPeer) Close() error      { panic("templates must not control the peer") }

type metadataRequest struct {
	conn      connection.Connection
	selection connection.Selection
}

func (r metadataRequest) Context() context.Context          { return context.Background() }
func (r metadataRequest) Connection() connection.Connection { return r.conn }
func (r metadataRequest) Selection() connection.Selection   { return r.selection }

func newMetadataConnection(t *testing.T) *metadataConnection {
	t.Helper()
	id, err := connection.NewId()
	require.NoError(t, err)
	host, err := bnet.NewHost("192.0.2.7")
	require.NoError(t, err)
	return &metadataConnection{id: id, peer: &metadataPeer{user: "foo@bar", host: host}}
}

func TestConnectionTemplateViewProvidesStableTransportAndOriginalPeerMetadata(t *testing.T) {
	for _, transport := range []connection.Transport{connection.TransportSsh, connection.TransportHttp} {
		t.Run(string(transport), func(t *testing.T) {
			conn := newMetadataConnection(t)
			selection := connection.Selection{Transport: transport}
			if transport == connection.TransportHttp {
				selection.Host = "APP.EXAMPLE.ORG.:8443"
				selection.Slug = "Docker"
			}
			view, err := connection.TemplateViewOf(metadataRequest{conn: conn, selection: selection})
			require.NoError(t, err)
			root := map[string]any{"connection": view}
			actual, err := template.MustNewString(`{{.connection.id}}|{{.connection.transport}}|{{.connection.remote.user}}|{{.connection.remote.host}}`).Render(root)
			require.NoError(t, err)
			require.Equal(t, conn.id.String()+"|"+string(transport)+"|foo@bar|"+conn.peer.host.String(), actual)
			legacy, err := template.MustNewString(`{{.connection.Id}}|{{.connection.Remote.User}}|{{.connection.Selection.Transport}}`).Render(root)
			require.NoError(t, err)
			require.Equal(t, conn.id.String()+"|foo@bar|"+string(transport), legacy)
			if transport == connection.TransportHttp {
				actual, err = template.MustNewString(`{{.connection.http.host}}|{{.connection.http.slug}}`).Render(root)
				require.NoError(t, err)
				require.Equal(t, "app.example.org|Docker", actual)
			} else {
				actual, err = template.MustNewString(`{{if .connection.http}}unexpected{{else}}no-http-selection{{end}}`).Render(root)
				require.NoError(t, err)
				require.Equal(t, "no-http-selection", actual)
			}
			conn.peer.user = "changed-after-snapshot"
			actual, err = template.MustNewString(`{{.connection.remote.user}}`).Render(root)
			require.NoError(t, err)
			require.Equal(t, "foo@bar", actual)
		})
	}
}

func TestConnectionTemplateViewNeverExposesTransportControlsOrCredentials(t *testing.T) {
	view, err := connection.NewTemplateView(newMetadataConnection(t), connection.Selection{Transport: connection.TransportSsh})
	require.NoError(t, err)
	for _, source := range []string{`{{.connection.Close}}`, `{{.connection.Logger}}`, `{{.connection.Context}}`, `{{.connection.password}}`, `{{.connection.accessToken}}`, `{{.connection.cookie}}`, `{{.connection.remote.Close}}`} {
		t.Run(source, func(t *testing.T) {
			value, err := template.MustNewString(source).Render(map[string]any{"connection": view})
			require.Error(t, err)
			require.Empty(t, value)
			require.NotContains(t, err.Error(), "PRIVATE-CONNECTION-SENTINEL")
		})
	}
}

func TestConnectionTemplateViewIsolatesMutablePeerAddresses(t *testing.T) {
	t.Run("original cannot mutate snapshot", func(t *testing.T) {
		conn := newMetadataConnection(t)
		require.NotEmpty(t, conn.peer.host.IP)
		view, err := connection.NewTemplateView(conn, connection.Selection{Transport: connection.TransportSsh})
		require.NoError(t, err)
		conn.peer.host.IP[len(conn.peer.host.IP)-1] ^= 1
		require.NotEqual(t, "192.0.2.7", conn.peer.host.String(), "the source mutation must really change its address")
		require.Equal(t, "192.0.2.7", view.Remote().Host().String())
	})
	for _, spelling := range []string{"legacy Host method", "template host field"} {
		t.Run(spelling, func(t *testing.T) {
			conn := newMetadataConnection(t)
			view, err := connection.NewTemplateView(conn, connection.Selection{Transport: connection.TransportSsh})
			require.NoError(t, err)
			var address bnet.Host
			if spelling == "legacy Host method" {
				address = view.Remote().Host()
			} else {
				remote, found, err := view.GetField("remote")
				require.NoError(t, err)
				require.True(t, found)
				raw, found, err := remote.(interface {
					GetField(string) (any, bool, error)
				}).GetField("host")
				require.NoError(t, err)
				require.True(t, found)
				address = raw.(bnet.Host)
			}
			require.NotEmpty(t, address.IP)
			address.IP[len(address.IP)-1] ^= 1
			require.NotEqual(t, "192.0.2.7", address.String(), "the getter copy must be mutable without changing its owner")
			require.Equal(t, "192.0.2.7", view.Remote().Host().String())
			require.Equal(t, "192.0.2.7", conn.peer.host.String())
		})
	}
}

func TestConnectionTemplateViewRejectsInvalidSelectionsInsteadOfAssumingSsh(t *testing.T) {
	for _, selection := range []connection.Selection{{Transport: "unknown"}, {Transport: connection.TransportSsh, Slug: "docker"}, {Transport: connection.TransportHttp, Host: "app.example.org", Slug: "../docker"}} {
		_, err := connection.TemplateViewOf(metadataRequest{conn: newMetadataConnection(t), selection: selection})
		require.Error(t, err)
	}
	_, err := connection.NewTemplateView(nil, connection.Selection{Transport: connection.TransportSsh})
	require.Error(t, err)
}
