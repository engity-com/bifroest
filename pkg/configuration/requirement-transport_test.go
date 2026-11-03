package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestRequirementCombinesGeneralAndTransportRules(t *testing.T) {
	requirement := Requirement{
		IncludedRequestingName: common.MustNewRegexp(`^allowed`),
		Ssh:                    RequirementSsh{IncludedRequestingName: common.MustNewRegexp(`ssh$`)},
		Http:                   RequirementHttp{IncludedRequestingName: common.MustNewRegexp(`web$`), IncludedHost: common.MustNewRegexp(`^app\.example$`), IncludedSlug: common.MustNewRegexp(`^servers/foo$`)},
	}
	require.True(t, requirement.MatchesSsh("allowed-ssh"))
	require.False(t, requirement.MatchesSsh("other-ssh"))
	require.False(t, requirement.MatchesSsh("allowed-web"))
	require.True(t, requirement.MatchesHttp("allowed-web", "app.example", "servers/foo"))
	require.False(t, requirement.MatchesHttp("other-web", "app.example", "servers/foo"))
	require.False(t, requirement.MatchesHttp("allowed-ssh", "app.example", "servers/foo"))
	require.False(t, requirement.MatchesHttp("allowed-web", "other.example", "servers/foo"))
	require.False(t, requirement.MatchesHttp("allowed-web", "app.example", "servers/bar"))
}

func TestEmptyAndExcludedRequirementMatchers(t *testing.T) {
	var requirement Requirement
	require.True(t, requirement.MatchesSsh(""))
	require.True(t, requirement.MatchesHttp("", "app.example", ""))
	require.False(t, requirement.MatchesHttp("", "app.example", "foo"), "an empty slug rule pair only permits root")
	requirement.IncludedRequestingName = common.MustNewRegexp(`^sso$`)
	require.False(t, requirement.MatchesHttp("", "app.example", ""))
	requirement.IncludedRequestingName = common.MustNewRegexp("")
	requirement.Http.IncludedRequestingName = common.MustNewRegexp(`^$`)
	require.True(t, requirement.MatchesHttp("", "app.example", ""))
	requirement.Http.ExcludedSlug = common.MustNewRegexp(`^$`)
	require.False(t, requirement.MatchesHttp("", "app.example", ""))
	require.True(t, requirement.MatchesHttp("", "app.example", "foo"))
	requirement.Http.ExcludedHost = common.MustNewRegexp(`^app\.example$`)
	require.False(t, requirement.MatchesHttp("", "app.example", "foo"))
	requirement.Ssh.ExcludedRequestingName = common.MustNewRegexp(`^blocked$`)
	require.False(t, requirement.MatchesSsh("blocked"))
	requirement.ExcludedRequestingName = common.MustNewRegexp(`^$`)
	require.False(t, requirement.MatchesHttp("", "other.example", "foo"))
}

func TestHttpSlugOptInUsesOnlyTheTrulyEmptyPair(t *testing.T) {
	for _, test := range []struct {
		name, included, excluded string
		root, alias, other       bool
	}{
		{name: "absent pair", root: true},
		{name: "explicit root regex", included: "^$", root: true},
		{name: "explicit wildcard", included: ".*", root: true, alias: true, other: true},
		{name: "named aliases", included: "^(docker|bla-bla)$", alias: true},
		{name: "exclude root only", excluded: "^$", alias: true, other: true},
		{name: "exclusion still wins", included: ".*", excluded: "^bla-bla$", root: true, other: true},
		{name: "whitespace is not empty", included: " "},
		{name: "empty-matching regex is not empty", included: "(?:)", root: true, alias: true, other: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rules := RequirementHttp{IncludedSlug: common.MustNewRegexp(test.included), ExcludedSlug: common.MustNewRegexp(test.excluded)}
			require.Equal(t, test.root, rules.MatchesSlug(""))
			require.Equal(t, test.alias, rules.MatchesSlug("bla-bla"))
			require.Equal(t, test.other, rules.MatchesSlug("other"))
			require.Equal(t, test.included, rules.IncludedSlug.String(), "matching must not rewrite the configured expression")
			require.Equal(t, test.excluded, rules.ExcludedSlug.String())
			require.True(t, (Requirement{Http: rules}).MatchesSsh("unrelated"), "HTTP slug opt-in must not restrict SSH")
		})
	}
}

func TestTransportRequirementRoundTripAndValidation(t *testing.T) {
	var requirement Requirement
	require.NoError(t, yaml.Unmarshal([]byte(`includedRequestingName: '^allowed'
ssh:
  excludedRequestingName: 'ssh$'
http:
  includedRequestingName: '^allowed-web$'
  includedHost: '^app\.example$'
  excludedHost: '^blocked\.example$'
  includedSlug: '^servers/'
  excludedSlug: '/blocked$'
`), &requirement))
	encoded, err := yaml.Marshal(&requirement)
	require.NoError(t, err)
	var restored Requirement
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	require.True(t, requirement.IsEqualTo(restored))
	for _, source := range []string{"ssh:\n  includedHost: foo", "http:\n  includedHosts: foo", "http:\n  includedHost: '['"} {
		require.Error(t, yaml.Unmarshal([]byte(source), &restored))
	}
}
