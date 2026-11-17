package service

import (
	"testing"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestBrowserRootDirectoryDoesNotOfferRootAsLoginSlug(t *testing.T) {
	testBrowserLoginUi(t, true, "root-directory", func(conf *configuration.Configuration) {
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^Work$")
		other := conf.Flows[0]
		other.Name, other.DiscoverAsSlug = "other", "Other"
		other.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Other$")
		conf.Flows = append(conf.Flows, other)
	})
}

func TestBrowserSinglePublishedDirectorySelectsSlugWithoutAuthentication(t *testing.T) {
	testBrowserLoginUi(t, true, "single-root-directory", func(conf *configuration.Configuration) {
		conf.Flows[0].DiscoverAsSlug = "foo"
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^foo$")
	})
}

func TestBrowserActualRootAccessRemainsSelectable(t *testing.T) {
	testBrowserLoginUi(t, true, "root-access", func(conf *configuration.Configuration) {
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^(|Work)$")
	})
}

func TestBrowserTabHistoryPreservesEntryAliasAndRootDefinitionDefaults(t *testing.T) {
	testBrowserLoginUi(t, true, "slug-history", func(conf *configuration.Configuration) {
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^(Work|bla-bla)$")
		conf.Environments = configuration.Environments{"default": conf.Flows[0].Environment}
		conf.Authorizations = configuration.Authorizations{"default": conf.Flows[0].Authorization}
		conf.Flows[0].Environment = configuration.Environment{}
		conf.Flows[0].Authorization = configuration.Authorization{}
	})
}
