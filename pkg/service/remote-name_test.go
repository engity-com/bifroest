package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestWebRemoteNameSharesCredentialsWithoutChangingFlowScopeOrSessionOwner(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		original := conf.Flows[0]
		credentials := original.Authorization.V.(*configuration.AuthorizationSimple)
		credentials.RemoteName = template.MustNewString(`{{regexReplaceAll "@[^@]+$" .remote.user ""}}`)
		conf.Flows = nil
		for _, suffix := range []string{"node-a", "node-b"} {
			flow := original
			flow.Name = configuration.FlowName(suffix)
			flow.DiscoverAsSlug = suffix
			flow.Requirement.IncludedRequestingName = common.MustNewRegexp("@" + suffix + "$")
			flow.Requirement.Http.IncludedSlug = common.MustNewRegexp("^" + suffix + "$")
			conf.Flows = append(conf.Flows, flow)
		}
	})
	var first *webAccess
	for _, suffix := range []string{"node-a", "node-b"} {
		token := webTestToken(t, webTestPassword(handler, "alice@"+suffix, "correct", suffix))
		access := webTestAccess(t, svc, token, suffix)
		require.Equal(t, "alice", access.identity.Principal)
		require.Equal(t, "alice", access.identity.Subject)
		require.Equal(t, suffix, access.auth.Flow().String())
		require.Equal(t, "alice@"+suffix, access.auth.Remote().User())
		info, err := access.auth.FindSession().Info(t.Context())
		require.NoError(t, err)
		last, err := info.LastAccessed(t.Context())
		require.NoError(t, err)
		require.Equal(t, "alice@"+suffix, last.Remote().User())
		if first == nil {
			first = access
		} else {
			require.NotEqual(t, first.auth.FindSession().Id(), access.auth.FindSession().Id())
		}
	}
	for _, attempt := range []struct{ name, slug, password string }{
		{"alice@node-a", "node-b", "correct"},
		{"alice@node-b", "node-a", "correct"},
		{"alice@node-a", "node-a", "wrong"},
		{"alice@node-c", "node-a", "correct"},
	} {
		response := webTestPassword(handler, attempt.name, attempt.password, attempt.slug)
		require.Equal(t, http.StatusUnauthorized, response.Code)
		require.NotContains(t, response.Body.String(), "accessToken")
	}
}
