package configuration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
)

const transportTestFlow = `name: test
authorization:
  type: none
environment:
  type: dummy
`

func TestFlowTransportDefaultsPreserveExistingConfigurations(t *testing.T) {
	var flow Flow
	require.True(t, flow.Ssh.IsEnabled())
	require.True(t, flow.Http.IsEnabled())
	require.True(t, flow.Http.RequestUserEnabled())
	require.NoError(t, yaml.Unmarshal([]byte(transportTestFlow), &flow))
	require.True(t, flow.Ssh.IsEnabled())
	require.True(t, flow.Http.IsEnabled())
	require.True(t, flow.Http.RequestUserEnabled())
	encoded, err := yaml.Marshal(&flow)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "ssh:")
	require.NotContains(t, string(encoded), "http:")

	explicit := flow
	yes := true
	explicit.Ssh.Enabled, explicit.Http.Enabled, explicit.Http.RequestUser = &yes, &yes, &yes
	require.True(t, flow.IsEqualTo(explicit))
}

func TestFlowTransportFlagsRoundTripIndependently(t *testing.T) {
	for _, test := range []struct {
		options         string
		ssh, http, user bool
	}{
		{"ssh:\n  enabled: false\n", false, true, true},
		{"http:\n  enabled: false\n", true, false, true},
		{"http:\n  requestUser: false\n", true, true, false},
		{"ssh:\n  enabled: false\nhttp:\n  enabled: false\n  requestUser: false\n", false, false, false},
	} {
		t.Run(test.options, func(t *testing.T) {
			var flow Flow
			require.NoError(t, yaml.Unmarshal([]byte(transportTestFlow+test.options), &flow))
			require.Equal(t, test.ssh, flow.Ssh.IsEnabled())
			require.Equal(t, test.http, flow.Http.IsEnabled())
			require.Equal(t, test.user, flow.Http.RequestUserEnabled())
			encoded, err := yaml.Marshal(&flow)
			require.NoError(t, err)
			var restored Flow
			require.NoError(t, yaml.Unmarshal(encoded, &restored))
			require.True(t, flow.IsEqualTo(restored))
		})
	}
}

func TestFlowTransportRejectsUnknownNonBooleanAndNullFields(t *testing.T) {
	for _, options := range []string{
		"ssh: null", "http: null", "ssh: false", "http: false", "ssh:\n  enabled: null", "http:\n  enabled: null",
		"http:\n  requestUser: null", "ssh:\n  enabled: disabled", "http:\n  enabled: 0", "http:\n  enable: false",
		"ssh:\n  requestUser: false", "unused: &nothing null\nhttp:\n  enabled: *nothing", "unused: &nothing null\nssh: *nothing",
		"<<: {ssh: null}", "<<: {http: null}", "<<: {http: {enabled: null}}",
		"http: {enabled: 'false'}", "http: {requestUser: yes}",
	} {
		t.Run(options, func(t *testing.T) {
			var flow Flow
			require.Error(t, yaml.Unmarshal([]byte(transportTestFlow+options+"\n"), &flow))
		})
	}
}

func TestFlowTransportSupportsValidAliasesAndFlowMerges(t *testing.T) {
	for _, source := range []string{
		"unused: &off false\nhttp:\n  enabled: *off\n",
		"unused: &transport {enabled: false}\nhttp: *transport\n",
		"<<: {http: {enabled: false}}\n",
	} {
		var flow Flow
		require.NoError(t, yaml.Unmarshal([]byte(transportTestFlow+source), &flow))
		require.False(t, flow.Http.IsEnabled())
		require.True(t, flow.Ssh.IsEnabled())
	}
}

func TestFlowDiscoverySlugValidation(t *testing.T) {
	for _, slug := range []string{"foo", "servers/Foo9", strings.Repeat("a", 64)} {
		var flow Flow
		require.NoError(t, yaml.Unmarshal([]byte(transportTestFlow+"discoverAsSlug: "+slug), &flow))
		require.Equal(t, slug, flow.DiscoverAsSlug)
	}
	for _, slug := range []string{"/foo", "foo/", "foo/bar/baz", "_bifroest", "foo-bar", strings.Repeat("a", 65)} {
		var flow Flow
		require.Error(t, yaml.Unmarshal([]byte(transportTestFlow+"discoverAsSlug: "+slug), &flow))
	}
}

func TestHttpDiscoveryIsExplicitOrderedAndHostScoped(t *testing.T) {
	no := false
	flows := Flows{
		{Name: "not-published"},
		{Name: "first", DiscoverAsSlug: "servers/First"},
		{Name: "disabled", DiscoverAsSlug: "disabled", Http: FlowHttp{Enabled: &no}},
		{Name: "other-host", DiscoverAsSlug: "second", Requirement: Requirement{Http: RequirementHttp{IncludedHost: common.MustNewRegexp(`^other\.example$`)}}},
		{Name: "last", DiscoverAsSlug: "last"},
	}
	slugs, err := flows.HttpDiscovery("APP.EXAMPLE:443")
	require.NoError(t, err)
	require.Equal(t, []string{"servers/First", "last"}, slugs)
	require.NoError(t, flows.ValidateHttpDiscovery([]string{"app.example", "other.example"}))
	name, fixed, err := flows.ResolveHttpSlug("app.example", "servers/First")
	require.NoError(t, err)
	require.True(t, fixed)
	require.Equal(t, FlowName("first"), name)
	for _, slug := range []string{"", "unknown", "disabled", "second"} {
		_, fixed, err := flows.ResolveHttpSlug("app.example", slug)
		require.NoError(t, err)
		require.False(t, fixed)
	}
}

func TestHttpDiscoveryRejectsCollisionsOnlyOnOverlappingDomains(t *testing.T) {
	flows := Flows{
		{Name: "first", DiscoverAsSlug: "foo", Requirement: Requirement{Http: RequirementHttp{IncludedHost: common.MustNewRegexp(`^first\.example$`)}}},
		{Name: "second", DiscoverAsSlug: "foo", Requirement: Requirement{Http: RequirementHttp{IncludedHost: common.MustNewRegexp(`^second\.example$`)}}},
	}
	require.NoError(t, flows.ValidateHttpDiscovery([]string{"first.example", "second.example"}))
	flows[1].Requirement.Http.IncludedHost = common.MustNewRegexp(`\.example$`)
	require.ErrorContains(t, flows.ValidateHttpDiscovery([]string{"first.example", "second.example"}), "same slug")
	_, _, err := flows.ResolveHttpSlug("first.example", "foo")
	require.ErrorContains(t, err, "multiple flows")
	no := false
	flows[1].Http.Enabled = &no
	require.NoError(t, flows.ValidateHttpDiscovery([]string{"first.example"}))
}
