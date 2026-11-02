package authorization

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
)

// All inherited authentication methods intentionally panic through the nil
// embedded interface if discovery ever attempts authorization or restoration.
type httpLoginDescriptionTestAuthorizer struct {
	CloseableAuthorizer
	capabilities AuthenticationCapabilities
	inputs       []DiscoveryInput
}

func (this *httpLoginDescriptionTestAuthorizer) AuthenticationCapabilities(input DiscoveryInput) AuthenticationCapabilities {
	this.inputs = append(this.inputs, input)
	return this.capabilities
}

func newHttpLoginDescriptionTestFacade(flows configuration.Flows, capabilities []AuthenticationCapabilities) (*AuthorizerFacade, []*httpLoginDescriptionTestAuthorizer) {
	facade := &AuthorizerFacade{flows: flows, observer: func(context.Context, FlowAuthorizationObservation) error {
		panic("discovery must not invoke authentication observers")
	}}
	providers := make([]*httpLoginDescriptionTestAuthorizer, len(flows))
	for index, flow := range flows {
		provider := &httpLoginDescriptionTestAuthorizer{capabilities: capabilities[index]}
		providers[index] = provider
		facade.entries = append(facade.entries, facaded{
			CloseableAuthorizer: provider, capabilityProvider: provider,
			flow: flow.Name, requirement: &flow.Requirement, http: flow.Http, ssh: flow.Ssh,
		})
	}
	return facade, providers
}

func TestDescribeHttpLoginDeduplicatesAndOrdersMethodsByInputMode(t *testing.T) {
	no := false
	unnamed := selectionTestFlow("unnamed-first")
	unnamed.Http.RequestUser = &no
	named := selectionTestFlow("named-second")
	namedDuplicate := selectionTestFlow("named-duplicate")
	nonKey := selectionTestFlow("non-key-does-not-relax-certificate-hint")
	all := AuthenticationCapabilities{Password: true, KeyboardInteractive: true, PublicKey: true, Secretless: true, SessionPublicKey: true, PublicKeyCertificateRequired: true}
	facade, providers := newHttpLoginDescriptionTestFacade(configuration.Flows{unnamed, named, namedDuplicate, nonKey}, []AuthenticationCapabilities{
		all, all, {PublicKey: true}, {Password: true},
	})
	expected := HttpLoginDescription{Available: true, Options: []LoginOption{
		{Method: LoginMethodPassword, RequestUser: true},
		{Method: LoginMethodKeyboardInteractive, RequestUser: true},
		{Method: LoginMethodPublicKey, RequestUser: true}, // Raw-key candidate relaxes only this group's hint.
		{Method: LoginMethodNone, RequestUser: true},
		{Method: LoginMethodPassword},
		{Method: LoginMethodKeyboardInteractive},
		{Method: LoginMethodPublicKey, CertificateRequired: true},
		{Method: LoginMethodNone},
	}}
	for range 3 {
		description, err := facade.DescribeHttpLogin("APP.EXAMPLE.:00443", "Work")
		require.NoError(t, err)
		require.Equal(t, expected, description)
		require.Len(t, description.Options, 8)
	}
	for index, provider := range providers {
		require.Equal(t, []DiscoveryInput{
			{Transport: connection.TransportHttp, RequestingName: index != 0},
			{Transport: connection.TransportHttp, RequestingName: index != 0},
			{Transport: connection.TransportHttp, RequestingName: index != 0},
		}, provider.inputs)
	}
}

func TestDescribeHttpLoginCertificateHintAndIsOrderIndependent(t *testing.T) {
	for _, rawFirst := range []bool{false, true} {
		cert, raw := AuthenticationCapabilities{PublicKey: true, PublicKeyCertificateRequired: true}, AuthenticationCapabilities{PublicKey: true}
		capabilities := []AuthenticationCapabilities{cert, raw, cert}
		if rawFirst {
			capabilities = []AuthenticationCapabilities{raw, cert, cert}
		}
		facade, _ := newHttpLoginDescriptionTestFacade(configuration.Flows{selectionTestFlow("first"), selectionTestFlow("second"), selectionTestFlow("third")}, capabilities)
		description, err := facade.DescribeHttpLogin("app.example", "Work")
		require.NoError(t, err)
		require.Equal(t, []LoginOption{{Method: LoginMethodPublicKey, RequestUser: true}}, description.Options)
	}
	// Neither a session-only key path nor a non-key flow may relax the hint.
	facade, _ := newHttpLoginDescriptionTestFacade(configuration.Flows{selectionTestFlow("cert"), selectionTestFlow("session")}, []AuthenticationCapabilities{
		{PublicKey: true, PublicKeyCertificateRequired: true}, {SessionPublicKey: true},
	})
	description, err := facade.DescribeHttpLogin("app.example", "Work")
	require.NoError(t, err)
	require.Equal(t, []LoginOption{{Method: LoginMethodPublicKey, RequestUser: true, CertificateRequired: true}}, description.Options)
}

func TestDescribeHttpLoginMatchesRequirementsWithoutProbingUsernames(t *testing.T) {
	no := false
	for _, test := range []struct {
		name      string
		configure func(*configuration.Flow)
		available bool
	}{
		{name: "defaults", available: true},
		{name: "SSH disabled does not disable HTTP", configure: func(f *configuration.Flow) { f.Ssh.Enabled = &no }, available: true},
		{name: "HTTP disabled", configure: func(f *configuration.Flow) { f.Http.Enabled = &no }},
		{name: "included host mismatch", configure: func(f *configuration.Flow) {
			f.Requirement.Http.IncludedHost = common.MustNewRegexp(`^other\.example$`)
		}},
		{name: "excluded host", configure: func(f *configuration.Flow) { f.Requirement.Http.ExcludedHost = common.MustNewRegexp(`^app\.example$`) }},
		{name: "included slug mismatch", configure: func(f *configuration.Flow) { f.Requirement.Http.IncludedSlug = common.MustNewRegexp(`^work$`) }},
		{name: "excluded slug", configure: func(f *configuration.Flow) { f.Requirement.Http.ExcludedSlug = common.MustNewRegexp(`^Work$`) }},
		{name: "canonical host and exact slug", configure: func(f *configuration.Flow) {
			f.Requirement.Http.IncludedHost = common.MustNewRegexp(`^app\.example$`)
			f.Requirement.Http.IncludedSlug = common.MustNewRegexp(`^Work$`)
		}, available: true},
		{name: "unknown name does not reject named flow", configure: func(f *configuration.Flow) {
			f.Requirement.IncludedRequestingName = common.MustNewRegexp(`^alice$`)
			f.Requirement.Http.IncludedRequestingName = common.MustNewRegexp(`^alice$`)
		}, available: true},
		{name: "unknown name is not tested as empty", configure: func(f *configuration.Flow) {
			f.Requirement.ExcludedRequestingName = common.MustNewRegexp(`^$`)
			f.Requirement.Http.ExcludedRequestingName = common.MustNewRegexp(`^$`)
		}, available: true},
		{name: "nameless defaults", configure: func(f *configuration.Flow) { f.Http.RequestUser = &no }, available: true},
		{name: "nameless requires empty name", configure: func(f *configuration.Flow) {
			f.Http.RequestUser = &no
			f.Requirement.IncludedRequestingName = common.MustNewRegexp(`^alice$`)
		}},
		{name: "nameless HTTP name restriction", configure: func(f *configuration.Flow) {
			f.Http.RequestUser = &no
			f.Requirement.Http.IncludedRequestingName = common.MustNewRegexp(`^alice$`)
		}},
		{name: "nameless excluded empty general name", configure: func(f *configuration.Flow) {
			f.Http.RequestUser = &no
			f.Requirement.ExcludedRequestingName = common.MustNewRegexp(`^$`)
		}},
		{name: "nameless excluded empty HTTP name", configure: func(f *configuration.Flow) {
			f.Http.RequestUser = &no
			f.Requirement.Http.ExcludedRequestingName = common.MustNewRegexp(`^$`)
		}},
		{name: "nameless explicit empty name", configure: func(f *configuration.Flow) {
			f.Http.RequestUser = &no
			f.Requirement.IncludedRequestingName = common.MustNewRegexp(`^$`)
			f.Requirement.Http.IncludedRequestingName = common.MustNewRegexp(`^$`)
		}, available: true},
		{name: "SSH names do not restrict HTTP", configure: func(f *configuration.Flow) {
			f.Http.RequestUser = &no
			f.Requirement.Ssh.IncludedRequestingName = common.MustNewRegexp(`^alice$`)
		}, available: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := selectionTestFlow("selected")
			if test.configure != nil {
				test.configure(&flow)
			}
			facade, providers := newHttpLoginDescriptionTestFacade(configuration.Flows{flow}, []AuthenticationCapabilities{{Secretless: true}})
			description, err := facade.DescribeHttpLogin("APP.EXAMPLE.:443", "Work")
			require.NoError(t, err)
			require.Equal(t, test.available, description.Available)
			if test.available {
				require.Equal(t, []LoginOption{{Method: LoginMethodNone, RequestUser: flow.Http.RequestUserEnabled()}}, description.Options)
				require.Len(t, providers[0].inputs, 1)
			} else {
				require.Empty(t, description.Options)
				require.Empty(t, providers[0].inputs, "ineligible flows must not reach capability providers")
			}
		})
	}
}

func TestDescribeHttpLoginPublishedSlugNeverFallsThrough(t *testing.T) {
	no := false
	for _, test := range []struct {
		name      string
		configure func(*configuration.Flow)
		possible  bool
		available bool
	}{
		{name: "published takes precedence over first generic flow", possible: true, available: true},
		{name: "zero methods still pins and remains available", available: true},
		{name: "published slug requirement mismatch", configure: func(f *configuration.Flow) { f.Requirement.Http.IncludedSlug = common.MustNewRegexp(`^Other$`) }},
		{name: "published nameless name mismatch", configure: func(f *configuration.Flow) {
			f.Http.RequestUser = &no
			f.Requirement.Http.IncludedRequestingName = common.MustNewRegexp(`^alice$`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			published := selectionTestFlow("published")
			published.DiscoverAsSlug = "Work"
			if test.configure != nil {
				test.configure(&published)
			}
			facade, providers := newHttpLoginDescriptionTestFacade(configuration.Flows{selectionTestFlow("generic-first"), published, selectionTestFlow("generic-last")}, []AuthenticationCapabilities{
				{Password: true}, {PublicKey: test.possible, PublicKeyCertificateRequired: true}, {Secretless: true},
			})
			description, err := facade.DescribeHttpLogin("app.example", "Work")
			require.NoError(t, err)
			require.Equal(t, test.available, description.Available)
			if test.possible {
				require.Equal(t, []LoginOption{{Method: LoginMethodPublicKey, RequestUser: true, CertificateRequired: true}}, description.Options)
			} else {
				require.Empty(t, description.Options)
			}
			require.Empty(t, providers[0].inputs)
			require.Empty(t, providers[2].inputs)
		})
	}
}

func TestDescribeHttpLoginNonPublishedSlugsUnionEligibleFlows(t *testing.T) {
	no := false
	published := selectionTestFlow("published")
	published.DiscoverAsSlug = "Work"
	disabled := selectionTestFlow("disabled")
	disabled.DiscoverAsSlug = "Off"
	disabled.Http.Enabled = &no
	otherHost := selectionTestFlow("other-host")
	otherHost.DiscoverAsSlug = "Elsewhere"
	otherHost.Requirement.Http.IncludedHost = common.MustNewRegexp(`^other\.example$`)
	facade, _ := newHttpLoginDescriptionTestFacade(configuration.Flows{selectionTestFlow("generic"), published, disabled, otherHost}, []AuthenticationCapabilities{
		{Password: true}, {PublicKey: true, PublicKeyCertificateRequired: true}, {Secretless: true}, {KeyboardInteractive: true},
	})
	for _, slug := range []string{"", "work", "Unknown", "Off", "Elsewhere"} {
		description, err := facade.DescribeHttpLogin("app.example", slug)
		require.NoError(t, err)
		require.Equal(t, HttpLoginDescription{Available: true, Options: []LoginOption{
			{Method: LoginMethodPassword, RequestUser: true}, {Method: LoginMethodPublicKey, RequestUser: true, CertificateRequired: true},
		}}, description, slug)
	}
}

func TestDescribeHttpLoginRootAvailabilityIsNotSpecialCased(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*configuration.Flow)
		available bool
	}{
		{name: "unrestricted root", available: true},
		{name: "discovery slug alone does not restrict root", configure: func(f *configuration.Flow) { f.DiscoverAsSlug = "Work" }, available: true},
		{name: "included non-root", configure: func(f *configuration.Flow) { f.Requirement.Http.IncludedSlug = common.MustNewRegexp(`^Work$`) }},
		{name: "excluded root", configure: func(f *configuration.Flow) { f.Requirement.Http.ExcludedSlug = common.MustNewRegexp(`^$`) }},
		{name: "explicit root", configure: func(f *configuration.Flow) { f.Requirement.Http.IncludedSlug = common.MustNewRegexp(`^$`) }, available: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			flow := selectionTestFlow("selected")
			if test.configure != nil {
				test.configure(&flow)
			}
			facade, _ := newHttpLoginDescriptionTestFacade(configuration.Flows{flow}, []AuthenticationCapabilities{{SessionPublicKey: true}})
			description, err := facade.DescribeHttpLogin("app.example", "")
			require.NoError(t, err)
			require.Equal(t, test.available, description.Available)
			require.NotNil(t, description.Options)
			require.Empty(t, description.Options, "remembered keys alone must not advertise primary key login")
		})
	}
}

func TestDescribeHttpLoginMalformedAmbiguousOrMissingProviderFailsClosed(t *testing.T) {
	for _, input := range []struct{ host, slug string }{
		{"", ""}, {"app.example/path", "Work"}, {"app.example", "../Work"},
		{"app.example", "/Work"}, {"app.example", "Work/"}, {"app.example", "a/b/c"},
	} {
		facade, providers := newHttpLoginDescriptionTestFacade(configuration.Flows{selectionTestFlow("generic")}, []AuthenticationCapabilities{{Secretless: true}})
		_, err := facade.DescribeHttpLogin(input.host, input.slug)
		require.Error(t, err)
		require.Empty(t, providers[0].inputs)
	}
	first, second := selectionTestFlow("first"), selectionTestFlow("second")
	first.DiscoverAsSlug, second.DiscoverAsSlug = "Work", "Work"
	facade, providers := newHttpLoginDescriptionTestFacade(configuration.Flows{first, second}, []AuthenticationCapabilities{{Secretless: true}, {Password: true}})
	_, err := facade.DescribeHttpLogin("app.example", "Work")
	require.ErrorContains(t, err, "multiple flows")
	require.Empty(t, providers[0].inputs)
	require.Empty(t, providers[1].inputs)

	facade.entries = facade.entries[:1]
	facade.flows = configuration.Flows{first}
	facade.entries[0].capabilityProvider = nil
	_, err = facade.DescribeHttpLogin("app.example", "Work")
	require.ErrorContains(t, err, "does not provide authentication capabilities")
	facade.entries = nil
	_, err = facade.DescribeHttpLogin("app.example", "Work")
	require.ErrorContains(t, err, "published HTTP flow has no authorizer")
}

func TestDescribeHttpLoginUsesRegisteredBuiltInProviders(t *testing.T) {
	no := false
	password := selectionTestFlow("password")
	password.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}}}
	secretless := selectionTestFlow("secretless")
	secretless.Http.RequestUser = &no
	facade, _ := newSelectionTestFacade(t, configuration.Flows{secretless, password})
	description, err := facade.DescribeHttpLogin("app.example", "Work")
	require.NoError(t, err)
	require.Equal(t, HttpLoginDescription{Available: true, Options: []LoginOption{
		{Method: LoginMethodPassword, RequestUser: true}, {Method: LoginMethodKeyboardInteractive, RequestUser: true}, {Method: LoginMethodNone},
	}}, description)

	var empty AuthorizerFacade
	description, err = empty.DescribeHttpLogin("app.example", "")
	require.NoError(t, err)
	require.False(t, description.Available)
	require.NotNil(t, description.Options)
	require.Empty(t, description.Options)
}

func TestLoginOptionWireContractKeepsExplicitFalseValues(t *testing.T) {
	encoded, err := json.Marshal(LoginOption{Method: LoginMethodNone})
	require.NoError(t, err)
	require.JSONEq(t, `{"method":"none","requestUser":false,"certificateRequired":false}`, string(encoded))
}
