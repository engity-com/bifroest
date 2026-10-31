package net

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalHttpHost(t *testing.T) {
	for _, test := range []struct{ input, expected string }{
		{"EXAMPLE.org", "example.org"},
		{"Example.org.:443", "example.org"},
		{"example.org:8443", "example.org"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"localhost", "localhost"},
		{"127.0.0.1:443", "127.0.0.1"},
		{"[2001:0db8::1]:443", "[2001:db8::1]"},
		{"[::1]", "[::1]"},
		{"[::ffff:192.0.2.1]:443", "[::ffff:192.0.2.1]"},
	} {
		t.Run(test.input, func(t *testing.T) {
			actual, err := CanonicalHttpHost(test.input)
			require.NoError(t, err)
			require.Equal(t, test.expected, actual)
			repeated, err := CanonicalHttpHost(actual)
			require.NoError(t, err)
			require.Equal(t, actual, repeated)
		})
	}
}

func TestCanonicalHttpHostRejectsMalformedAuthority(t *testing.T) {
	for _, value := range []string{
		"", " example.org", "example.org\n", "example.org\x00", "user@example.org", "https://example.org",
		"example.org/path", "example.org?query", "example.org#fragment", "example.org\\path", "example..org",
		"-example.org", "example-.org", "example_.org", "example.org..", "example.org:", "example.org:0",
		"example.org:65536", "example.org:+443", "example.org:https", "2001:db8::1", "[broken]:443",
		"[example.org]:443", "[127.0.0.1]:443", "[fe80::1%lo]:443", "[::1]:", strings.Repeat("a", 64) + ".org",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := CanonicalHttpHost(value)
			require.Error(t, err)
		})
	}
}

func TestHttpSlugFromURL(t *testing.T) {
	for _, test := range []struct{ raw, slug string }{
		{"https://example.org", ""}, {"/", ""}, {"/?next=/other", ""},
		{"/foo", "foo"}, {"/servers/Foo9", "servers/Foo9"},
		{"/servers/foo?next=/other#fragment", "servers/foo"},
		{"/" + strings.Repeat("a", 64) + "/" + strings.Repeat("B", 64), strings.Repeat("a", 64) + "/" + strings.Repeat("B", 64)},
	} {
		t.Run(test.raw, func(t *testing.T) {
			value, err := url.Parse(test.raw)
			require.NoError(t, err)
			actual, err := HttpSlugFromURL(value)
			require.NoError(t, err)
			require.Equal(t, test.slug, actual)
		})
	}
}

func TestHttpSlugRejectsAliasesAndInternalPaths(t *testing.T) {
	for _, path := range []string{
		"foo", "/foo/", "/foo//bar", "/one/two/three", "/.", "/..", "/foo/..", "/foo-bar", "/é",
		"/_bifroest", "/_bifroest/api", "/_bifroest/assets/main.js", "/assets/main.js", "/%66oo", "/foo%2fbar", "/foo%2Fbar", "/foo%252fbar",
		"/" + strings.Repeat("a", 65),
	} {
		t.Run(path, func(t *testing.T) {
			value, err := url.Parse(path)
			require.NoError(t, err)
			_, err = HttpSlugFromURL(value)
			require.Error(t, err)
		})
	}
	_, err := HttpSlugFromURL(nil)
	require.Error(t, err)
	_, err = HttpSlugFromURL(&url.URL{Path: "/foo", RawPath: "/%invalid"})
	require.Error(t, err)
}
