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

var testSbomPlatform = bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}

func TestResolveBuildTimeUsesSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1789200000")

	actual, err := (&build{}).resolveTime()

	require.NoError(t, err)
	require.Equal(t, time.Date(2026, time.September, 12, 8, 0, 0, 0, time.UTC), actual)
}

func TestResolveBuildTimeRejectsInvalidSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "invalid")

	_, err := (&build{}).resolveTime()

	require.ErrorContains(t, err, "invalid SOURCE_DATE_EPOCH")
}

func TestNormalizeSpdxSbomIsDeterministic(t *testing.T) {
	filename := t.TempDir() + "/artifact.spdx.json"
	require.NoError(t, gos.WriteFile(filename, []byte(`{"creationInfo":{"created":"now"},"packages":[{"name":"artifact.tgz"}]}`), 0644))
	timestamp := time.Date(2026, time.September, 12, 8, 0, 0, 0, time.UTC)

	require.NoError(t, normalizeSbom(filename, testSbomPlatform, buildArtifactTypeArchive, "artifact.tgz", "sha256:123", timestamp))
	first, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.NoError(t, normalizeSbom(filename, testSbomPlatform, buildArtifactTypeArchive, "artifact.tgz", "sha256:123", timestamp))
	second, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, first, second)

	var document map[string]any
	require.NoError(t, json.Unmarshal(second, &document))
	require.Equal(t, "2026-09-12T08:00:00Z", document["creationInfo"].(map[string]any)["created"])
	require.Equal(t, "https://github.com/engity-com/bifroest/sbom/0608bca9d2e476321666779e9959e566ba9f4ee9815ee8318377719410db5083", document["documentNamespace"])
}

func TestNormalizeCycloneDxSbomIsDeterministic(t *testing.T) {
	filename := t.TempDir() + "/artifact.cdx.json"
	require.NoError(t, gos.WriteFile(filename, []byte(`{"metadata":{"timestamp":"now","component":{"bom-ref":"random"}},"serialNumber":"random"}`), 0644))
	timestamp := time.Date(2026, time.September, 12, 8, 0, 0, 0, time.UTC)

	require.NoError(t, normalizeSbom(filename, testSbomPlatform, buildArtifactTypeImage, "image", "sha256:123", timestamp))
	first, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.NoError(t, normalizeSbom(filename, testSbomPlatform, buildArtifactTypeImage, "image", "sha256:123", timestamp))
	second, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, first, second)

	var document map[string]any
	require.NoError(t, json.Unmarshal(second, &document))
	require.Equal(t, "2026-09-12T08:00:00Z", document["metadata"].(map[string]any)["timestamp"])
	require.Equal(t, "urn:uuid:95820dec-7494-5b6c-969b-099e626ffff3", document["serialNumber"])
	component := document["metadata"].(map[string]any)["component"].(map[string]any)
	require.Equal(t, "urn:bifroest:artifact:123", component["bom-ref"])
	require.Equal(t, "123", component["hashes"].([]any)[0].(map[string]any)["content"])
}

func TestNormalizeImageSpdxPurlIsCanonicalAndIdempotent(t *testing.T) {
	filename := t.TempDir() + "/image.spdx.json"
	raw := `{"creationInfo":{"created":"now"},"packages":[{"name":"image","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:oci/image@sha256%3A123?arch="}]}]}`
	require.NoError(t, gos.WriteFile(filename, []byte(raw), 0644))
	platform := bib.Platform{Os: sys.OsLinux, Arch: sys.ArchArmV7, Edition: sys.EditionGeneric}
	timestamp := time.Date(2026, time.September, 12, 8, 0, 0, 0, time.UTC)

	require.NoError(t, normalizeSbom(filename, platform, buildArtifactTypeImage, "image", "sha256:123", timestamp))
	first, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.NoError(t, normalizeSbom(filename, platform, buildArtifactTypeImage, "image", "sha256:123", timestamp))
	second, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, first, second)

	var document map[string]any
	require.NoError(t, json.Unmarshal(second, &document))
	references := document["packages"].([]any)[0].(map[string]any)["externalRefs"].([]any)
	require.Equal(t, "pkg:oci/image@sha256:123?arch=arm%2Fv7", references[0].(map[string]any)["referenceLocator"])
}
