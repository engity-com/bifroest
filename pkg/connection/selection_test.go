package connection

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type selectionTestContext struct{}

func (selectionTestContext) Context() context.Context { return context.Background() }
func (selectionTestContext) Connection() Connection   { return nil }

type selectionTestRequest struct {
	selectionTestContext
	selection Selection
}

func TestHttpLoginUserValidationDoesNotConflateSyntaxAndEligibility(t *testing.T) {
	for _, name := range []string{"", "ops", "  ops  ", "   ", "älice", strings.Repeat("x", 256), strings.Repeat("ä", 128)} {
		require.True(t, ValidHttpLoginUser(name), "%q", name)
	}
	for _, name := range []string{"bad\nname", "bad\tname", "bad\x00name", string([]byte{0xff}), strings.Repeat("x", 257), strings.Repeat("ä", 129)} {
		require.False(t, ValidHttpLoginUser(name), "%q", name)
	}
}

func (this selectionTestRequest) Selection() Selection { return this.selection }

func TestRequestSelectionDefaultsOnlyLegacyRequestsToSSH(t *testing.T) {
	selection, err := SelectionOf(selectionTestContext{})
	require.NoError(t, err)
	require.Equal(t, Selection{Transport: TransportSsh}, selection)
	for _, selection := range []Selection{{}, {Transport: "unknown"}, {Transport: TransportSsh, Host: "example.org"}, {Transport: TransportSsh, Slug: "foo"}, {Transport: TransportHttp}} {
		_, err := SelectionOf(selectionTestRequest{selection: selection})
		require.Error(t, err)
	}
}

func TestHttpRequestSelectionCanonicalizesHostWithoutChangingSlug(t *testing.T) {
	request := selectionTestRequest{selection: Selection{Transport: TransportHttp, Host: "EXAMPLE.org:443", Slug: "servers/Foo"}}
	selection, err := SelectionOf(request)
	require.NoError(t, err)
	require.Equal(t, "example.org", selection.Host)
	require.Equal(t, "servers/Foo", selection.Slug)
	require.Equal(t, "EXAMPLE.org:443", request.selection.Host)
	repeated, err := selection.Canonical()
	require.NoError(t, err)
	require.Equal(t, selection, repeated)
}

func TestHttpSelectionCanonicalizationIsIdempotentForIPv6(t *testing.T) {
	selection, err := (Selection{Transport: TransportHttp, Host: "[2001:0db8::1]:443", Slug: "foo"}).Canonical()
	require.NoError(t, err)
	require.Equal(t, "[2001:db8::1]", selection.Host)
	repeated, err := selection.Canonical()
	require.NoError(t, err)
	require.Equal(t, selection, repeated)
}
