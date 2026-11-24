package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReleaseDescriptionMarkersPreserveOutsideTextAndAreIdempotent(t *testing.T) {
	for _, test := range []struct {
		name, input, expected string
	}{
		{"empty", "", releaseArtifactsBegin + "\n\nNEW\n\n" + releaseArtifactsEnd + "\n"},
		{"append", "Manual notes", "Manual notes\n\n" + releaseArtifactsBegin + "\n\nNEW\n\n" + releaseArtifactsEnd + "\n"},
		{"placeholder", "Before\n<!-- release artifacts -->\nAfter", "Before\n" + releaseArtifactsBegin + "\n\nNEW\n\n" + releaseArtifactsEnd + "\nAfter"},
		{"pair", "Before\n<!-- begin: release artifacts -->old<!-- end: release artifacts -->\nAfter", "Before\n<!-- begin: release artifacts -->\n\nNEW\n\n<!-- end: release artifacts -->\nAfter"},
		{"unicode", "K ſ İ before\n" + releaseArtifactsPlaceholder + "\nafter", "K ſ İ before\n" + releaseArtifactsBegin + "\n\nNEW\n\n" + releaseArtifactsEnd + "\nafter"},
		{"CRLF", "Before\r\n" + releaseArtifactsPlaceholder + "\r\nAfter", "Before\r\n" + releaseArtifactsBegin + "\r\n\r\nNEW\r\n\r\n" + releaseArtifactsEnd + "\r\nAfter"},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := replaceReleaseArtifacts(test.input, "NEW\n")
			require.NoError(t, err)
			require.Equal(t, test.expected, actual)
			repeated, err := replaceReleaseArtifacts(actual, "NEW\n")
			require.NoError(t, err)
			require.Equal(t, actual, repeated)
		})
	}
}

func TestReleaseDescriptionMarkersRejectAmbiguousOrBrokenPairs(t *testing.T) {
	for _, body := range []string{
		releaseArtifactsBegin,
		releaseArtifactsEnd,
		releaseArtifactsEnd + releaseArtifactsBegin,
		releaseArtifactsBegin + releaseArtifactsBegin + releaseArtifactsEnd,
		releaseArtifactsBegin + releaseArtifactsEnd + releaseArtifactsEnd,
		releaseArtifactsPlaceholder + strings.ToLower(releaseArtifactsPlaceholder),
	} {
		t.Run(body, func(t *testing.T) {
			_, err := replaceReleaseArtifacts(body, "new")
			require.Error(t, err)
		})
	}
}

func TestReleaseDescriptionMarkerPairTakesPrecedenceOverPlaceholder(t *testing.T) {
	before := "Manual " + releaseArtifactsPlaceholder + "\n"
	body := before + releaseArtifactsBegin + "old" + releaseArtifactsEnd + "\nAfter"
	updated, err := replaceReleaseArtifacts(body, "new")
	require.NoError(t, err)
	require.Equal(t, before+releaseArtifactsBegin+"\n\nnew\n\n"+releaseArtifactsEnd+"\nAfter", updated)
}
