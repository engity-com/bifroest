package main

import (
	"encoding/json"
	gos "os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestBinaryMetadataRestoresPackagingInputs(t *testing.T) {
	build, bc := testReleaseManifestBuild(t)
	build.buildContextP.Store(bc)
	p := &bib.Platform{Os: sys.OsWindows, Arch: sys.ArchArm64, Edition: sys.EditionGeneric}
	binary := testReleaseManifestFile(t, bc, p, buildArtifactTypeBinary, "bifroest-windows-arm64-generic.exe", "binary", nil)
	notice := testReleaseManifestFile(t, bc, p, buildArtifactTypeNotice, "bifroest-windows-arm64-generic.third-party-notices.txt", "notice", nil)
	binary.thirdPartyNoticesFilepath = notice.filepath
	binary.thirdPartyLicenseInventory = &thirdPartyLicenseInventory{modules: []thirdPartyLicenseModule{{
		names: []string{"example.com/module"}, version: "v1.2.3", licenseExpression: "MIT",
	}}}
	require.NoError(t, build.binary.save(binary, notice))

	loaded, loadedNotice, err := build.binary.load(t.Context(), p)
	require.NoError(t, err)
	require.Equal(t, binary.filepath, loaded.filepath)
	require.Equal(t, notice.filepath, loadedNotice.filepath)
	require.Equal(t, notice.filepath, loaded.thirdPartyNoticesFilepath)
	require.Equal(t, binary.thirdPartyLicenseInventory, loaded.thirdPartyLicenseInventory)
}

func TestBinaryMetadataRejectsMissingAndModifiedInputs(t *testing.T) {
	build, bc := testReleaseManifestBuild(t)
	build.buildContextP.Store(bc)
	p := &bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionExtended}
	binary := testReleaseManifestFile(t, bc, p, buildArtifactTypeBinary, "bifroest-linux-amd64-extended", "binary", nil)
	notice := testReleaseManifestFile(t, bc, p, buildArtifactTypeNotice, "bifroest-linux-amd64-extended.third-party-notices.txt", "notice", nil)
	binary.thirdPartyNoticesFilepath = notice.filepath
	binary.thirdPartyLicenseInventory = &thirdPartyLicenseInventory{modules: []thirdPartyLicenseModule{{names: []string{"example.com/module"}, licenseExpression: "MIT"}}}

	_, _, err := build.binary.load(t.Context(), p)
	require.ErrorContains(t, err, "cannot load binary build metadata")
	require.NoError(t, build.binary.save(binary, notice))
	require.NoError(t, gos.WriteFile(binary.filepath, []byte("modified binary"), 0644))
	_, _, err = build.binary.load(t.Context(), p)
	require.ErrorContains(t, err, "has digest")
	require.NoError(t, gos.WriteFile(binary.filepath, []byte("binary"), 0644))
	require.NoError(t, gos.WriteFile(notice.filepath, []byte("modified notice"), 0644))
	_, _, err = build.binary.load(t.Context(), p)
	require.ErrorContains(t, err, "has digest")
	require.NoError(t, gos.WriteFile(notice.filepath, []byte("notice"), 0644))
	build.buildContextP.Store(&buildContext{build: build, version: bc.version, revision: bc.revision, vendor: bc.vendor, time: bc.time.Add(time.Second)})
	_, _, err = build.binary.load(t.Context(), p)
	require.ErrorContains(t, err, "does not match the expected build")
}

func TestBinaryMetadataRejectsWrongPlatformAndIncompleteInventory(t *testing.T) {
	build, bc := testReleaseManifestBuild(t)
	build.buildContextP.Store(bc)
	p := &bib.Platform{Os: sys.OsLinux, Arch: sys.ArchArmV6, Edition: sys.EditionGeneric}
	binary := testReleaseManifestFile(t, bc, p, buildArtifactTypeBinary, "bifroest-linux-armv6-generic", "binary", nil)
	notice := testReleaseManifestFile(t, bc, p, buildArtifactTypeNotice, "bifroest-linux-armv6-generic.third-party-notices.txt", "notice", nil)
	binary.thirdPartyNoticesFilepath = notice.filepath
	binary.thirdPartyLicenseInventory = &thirdPartyLicenseInventory{modules: []thirdPartyLicenseModule{{names: []string{"example.com/module"}, licenseExpression: "MIT"}}}
	require.NoError(t, build.binary.save(binary, notice))
	filename := build.binary.metadataFilepath(binary)
	raw, err := gos.ReadFile(filename)
	require.NoError(t, err)
	var metadata binaryBuildMetadata
	require.NoError(t, json.Unmarshal(raw, &metadata))

	metadata.Platform = "linux/riscv64/generic"
	modified, err := json.Marshal(metadata)
	require.NoError(t, err)
	require.NoError(t, gos.WriteFile(filename, modified, 0644))
	_, _, err = build.binary.load(t.Context(), p)
	require.ErrorContains(t, err, "does not match the expected build")

	metadata.Platform = p.String()
	metadata.Licenses[0].Expression = ""
	modified, err = json.Marshal(metadata)
	require.NoError(t, err)
	require.NoError(t, gos.WriteFile(filename, modified, 0644))
	_, _, err = build.binary.load(t.Context(), p)
	require.ErrorContains(t, err, "incomplete license data")
}

func TestBinaryOnlyRejectsEmptyPlatformSelection(t *testing.T) {
	build, _ := testReleaseManifestBuild(t)
	build.binaryMode = binaryBuildOnly
	build.rawStages = buildStages{buildStageBinary}
	build.oses = sys.Oses{sys.OsLinux}
	build.archs = sys.Archs{sys.ArchRiscV64}
	build.editions = sys.Editions{sys.EditionExtended}
	_, err := build.buildAll(t.Context(), false)
	require.ErrorContains(t, err, "no binary platforms match")
}
