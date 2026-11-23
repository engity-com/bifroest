// SPDX-License-Identifier: Apache-2.0

package main

import (
	gos "os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
)

func TestBuildDigestSortsAndIncludesAllPublishableFiles(t *testing.T) {
	build, buildContext := testReleaseManifestBuild(t)
	platform := &bib.Platform{}
	zNotice := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeNotice, "z-notice.txt", "notice", nil)
	zSbom := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, "z-sbom.spdx.json", "sbom", nil)
	aManifest := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeManifest, "a-manifest.json", "manifest", nil)
	binary := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeBinary, "binary", "binary", nil)

	created, err := build.digest.create(t.Context(), buildArtifacts{zNotice, binary, zSbom, aManifest})
	require.NoError(t, err)
	raw, err := gos.ReadFile(created[len(created)-1].filepath)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, lines, 2)
	require.True(t, strings.HasSuffix(lines[0], "  a-manifest.json"))
	require.True(t, strings.HasSuffix(lines[1], "  z-sbom.spdx.json"))
	require.NotContains(t, string(raw), "z-notice.txt")
}
