package session

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBrowserBindingSpecRequiresCanonicalHttpsScopeAndVerifiedIdentityShape(t *testing.T) {
	_, _, _, spec := browserBindingFixture(t)
	for _, origin := range []string{"https://app.example.org", "https://app.example.org:8443", "https://[2001:db8::1]", "https://xn--bcher-kva.example"} {
		value := spec
		value.Origin = origin
		require.NoError(t, value.Validate())
	}
	for _, origin := range []string{"", "http://app.example.org", "https://APP.example.org", "https://app.example.org.", "https://app.example.org:443", "https://app.example.org:08443", "https://app.example.org:0", "https://user@app.example.org", "https://app.example.org/", "https://app.example.org?", "https://app.example.org#fragment", "https://bücher.example"} {
		value := spec
		value.Origin = origin
		require.ErrorIs(t, value.Validate(), ErrInvalidBrowserBinding, origin)
	}
	for _, change := range []func(*BrowserBindingSpec){
		func(v *BrowserBindingSpec) { v.Slug = "Work/" }, func(v *BrowserBindingSpec) { v.Slug = "work//nested" },
		func(v *BrowserBindingSpec) { v.User = "name\x00" }, func(v *BrowserBindingSpec) { v.User = strings.Repeat("x", 257) },
		func(v *BrowserBindingSpec) { v.Identity.Subject = "" }, func(v *BrowserBindingSpec) { v.Identity.Principal = "" },
		func(v *BrowserBindingSpec) { v.Target = "client-selected-account" }, func(v *BrowserBindingSpec) { v.PublicKey = "private material" },
	} {
		value := spec
		change(&value)
		require.ErrorIs(t, value.Validate(), ErrInvalidBrowserBinding)
	}
}

func TestBrowserBindingEmptyOrNegativeIdleCannotCreateState(t *testing.T) {
	_, _, sess, spec := browserBindingFixture(t)
	for _, idle := range []time.Duration{0, -time.Second} {
		_, err := sess.CreateBrowserBinding(t.Context(), spec, idle)
		require.Error(t, err)
	}
	bindings, err := sess.BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Empty(t, bindings)
}
