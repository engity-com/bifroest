package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

const sshOnlyRemoteName = `{{if eq .connection.transport "ssh"}}{{regexReplaceAll "@[^@]+$" .remote.user ""}}{{else}}{{.remote.user}}{{end}}`

func TestRemoteNameCanStripSshSuffixWithoutChangingHttpUsernames(t *testing.T) {
	for _, kind := range []string{"simple", "htpasswd"} {
		for _, transport := range []connection.Transport{connection.TransportSsh, connection.TransportHttp} {
			t.Run(kind+"/"+string(transport), func(t *testing.T) {
				base := newFacadeSelectionRequest(t, "foo@bar")
				want := "foo"
				base.password = "ssh-secret"
				if transport == connection.TransportHttp {
					want = "foo@bar"
					base.password = "http-secret"
				}
				r := &mappingTestRequest{facadeSelectionRequest: base, selection: connection.Selection{Transport: transport}}
				if transport == connection.TransportHttp {
					r.selection.Host = "app.example.org"
					r.selection.Slug = "docker"
				}
				var authorizer Authorizer
				if kind == "simple" {
					authorizer = &SimpleAuthorizer{flow: "docker", conf: &configuration.AuthorizationSimple{RemoteName: template.MustNewString(sshOnlyRemoteName), Entries: configuration.AuthorizationSimpleEntries{{Name: "foo", Password: crypto.Password("plain:ssh-secret")}, {Name: "foo@bar", Password: crypto.Password("plain:http-secret")}}}}
				} else {
					sshHash, err := bcrypt.GenerateFromPassword([]byte("ssh-secret"), bcrypt.MinCost)
					require.NoError(t, err)
					httpHash, err := bcrypt.GenerateFromPassword([]byte("http-secret"), bcrypt.MinCost)
					require.NoError(t, err)
					var entries crypto.Htpasswd
					require.NoError(t, entries.Set("foo:"+string(sshHash)+"\nfoo@bar:"+string(httpHash)))
					authorizer = &HtpasswdAuthorizer{flow: "docker", conf: &configuration.AuthorizationHtpasswd{RemoteName: template.MustNewString(sshOnlyRemoteName), Entries: entries}}
				}
				result, err := authorizer.AuthorizePassword(r)
				require.NoError(t, err)
				require.True(t, result.IsAuthorized())
				identity, err := AuthenticationOf(result)
				require.NoError(t, err)
				require.Equal(t, want, identity.Subject)
				require.Equal(t, "foo@bar", result.Remote().User())
				if transport == connection.TransportHttp {
					base.password = "ssh-secret"
				} else {
					base.password = "http-secret"
				}
				denied, err := authorizer.AuthorizePassword(r)
				require.NoError(t, err)
				require.False(t, denied.IsAuthorized())
				require.Equal(t, 1, sessionCount(t, base.repository))
			})
		}
	}
}

func TestResumeKeyRenderingRetainsHttpTransportInsteadOfFallingBackToSsh(t *testing.T) {
	base := newFacadeSelectionRequest(t, "foo@bar")
	r := &mappingTestRequest{facadeSelectionRequest: base, selection: connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "docker"}}
	wrapped := resumePublicKeyRequest{Request: r, key: base.key}
	actual, err := template.MustNewString(`{{.connection.transport}}|{{.connection.http.slug}}`).Render(remoteNameRequest{Request: wrapped})
	require.NoError(t, err)
	require.Equal(t, "http|docker", actual)
}
