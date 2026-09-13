package main

import (
	"encoding/json"
	gos "os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNormalizeSpdxSbomEnrichesLicenses(t *testing.T) {
	filename := t.TempDir() + "/artifact.spdx.json"
	require.NoError(t, gos.WriteFile(filename, []byte(`{
  "creationInfo": {"created": "now"},
  "packages": [
    {"SPDXID":"SPDXRef-Root","name":"artifact.tgz","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION"},
    {"SPDXID":"SPDXRef-Project","name":"github.com/engity-com/bifroest","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/github.com/engity-com/bifroest"}]},
    {"SPDXID":"SPDXRef-Dependency","name":"example.com/dependency","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/dependency@v1.2.3"}]},
    {"SPDXID":"SPDXRef-Stdlib","name":"stdlib","licenseConcluded":"NOASSERTION","licenseDeclared":"BSD-3-Clause","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/stdlib@1.27.0"}]},
    {"SPDXID":"SPDXRef-BaseImageGoPackage","name":"example.com/base-image","licenseConcluded":"NOASSERTION","licenseDeclared":"NOASSERTION","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/base-image@v2.0.0"}]}
  ],
  "relationships": [
    {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-Root"},
    {"spdxElementId":"SPDXRef-Dependency","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-Project"},
    {"spdxElementId":"SPDXRef-Stdlib","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-Project"}
  ]
}`), 0644))
	inventory := testThirdPartyLicenseInventory()
	timestamp := time.Date(2026, time.September, 12, 8, 0, 0, 0, time.UTC)

	require.NoError(t, normalizeSbom(filename, testSbomPlatform, buildArtifactTypeArchive, "artifact.tgz", "sha256:123", timestamp, inventory))
	first, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.NoError(t, normalizeSbom(filename, testSbomPlatform, buildArtifactTypeArchive, "artifact.tgz", "sha256:123", timestamp, inventory))
	second, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, first, second)

	var document map[string]any
	require.NoError(t, json.Unmarshal(second, &document))
	packages := jsonObjects(document["packages"])
	require.Equal(t, "Apache-2.0", jsonObjectWith(packages, "name", "artifact.tgz")["licenseDeclared"])
	require.Equal(t, "Apache-2.0", jsonObjectWith(packages, "name", projectModule)["licenseDeclared"])
	require.Equal(t, "MIT", jsonObjectWith(packages, "name", "example.com/dependency")["licenseDeclared"])
	require.Equal(t, "BSD-3-Clause", jsonObjectWith(packages, "name", "stdlib")["licenseDeclared"])
	require.Equal(t, "BSD-3-Clause", jsonObjectWith(packages, "SPDXID", modifiedGoSourcesSpdxID)["licenseDeclared"])
	require.Equal(t, "MPL-2.0", jsonObjectWith(packages, "SPDXID", mozillaCaDataSpdxID)["licenseDeclared"])
	require.Equal(t, "NOASSERTION", jsonObjectWith(packages, "name", "example.com/dependency")["licenseConcluded"])
	require.Equal(t, "NOASSERTION", jsonObjectWith(packages, "name", "example.com/base-image")["licenseDeclared"])

	relationships := jsonObjects(document["relationships"])
	require.NotNil(t, jsonObjectWith(relationships, "relatedSpdxElement", modifiedGoSourcesSpdxID))
	require.NotNil(t, jsonObjectWith(relationships, "relatedSpdxElement", mozillaCaDataSpdxID))
}

func TestNormalizeCycloneDxSbomEnrichesLicenses(t *testing.T) {
	filename := t.TempDir() + "/artifact.cdx.json"
	require.NoError(t, gos.WriteFile(filename, []byte(`{
  "metadata":{"timestamp":"now","component":{"bom-ref":"random","name":"image"}},
  "serialNumber":"random",
  "components":[
    {"bom-ref":"project","name":"github.com/engity-com/bifroest","purl":"pkg:golang/github.com/engity-com/bifroest"},
    {"bom-ref":"dependency","name":"example.com/dependency","purl":"pkg:golang/example.com/dependency@v1.2.3"},
    {"bom-ref":"stdlib","name":"stdlib","purl":"pkg:golang/stdlib@1.27.0","licenses":[{"license":{"id":"BSD-3-Clause"}}]},
    {"bom-ref":"base-image","name":"example.com/base-image","purl":"pkg:golang/example.com/base-image@v2.0.0"}
  ],
  "dependencies":[{"ref":"project","dependsOn":["dependency","stdlib"]}]
}`), 0644))
	inventory := testThirdPartyLicenseInventory()
	timestamp := time.Date(2026, time.September, 12, 8, 0, 0, 0, time.UTC)

	require.NoError(t, normalizeSbom(filename, testSbomPlatform, buildArtifactTypeImage, "image", "sha256:123", timestamp, inventory))
	first, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.NoError(t, normalizeSbom(filename, testSbomPlatform, buildArtifactTypeImage, "image", "sha256:123", timestamp, inventory))
	second, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, first, second)

	var document map[string]any
	require.NoError(t, json.Unmarshal(second, &document))
	root := document["metadata"].(map[string]any)["component"].(map[string]any)
	require.Equal(t, "Apache-2.0", testCycloneDxLicense(root))
	components := jsonObjects(document["components"])
	require.Equal(t, "Apache-2.0", testCycloneDxLicense(jsonObjectWith(components, "name", projectModule)))
	require.Equal(t, "MIT", testCycloneDxLicense(jsonObjectWith(components, "name", "example.com/dependency")))
	require.Equal(t, "BSD-3-Clause", testCycloneDxLicense(jsonObjectWith(components, "bom-ref", modifiedGoSourcesCycloneDxRef)))
	require.Equal(t, "MPL-2.0", testCycloneDxLicense(jsonObjectWith(components, "bom-ref", mozillaCaDataCycloneDxRef)))
	_, baseImageLicensed := jsonObjectWith(components, "bom-ref", "base-image")["licenses"]
	require.False(t, baseImageLicensed)

	dependencies := jsonObjects(document["dependencies"])
	projectDependencies := stringsFromJsonArray(jsonObjectWith(dependencies, "ref", "project")["dependsOn"])
	require.Contains(t, projectDependencies, modifiedGoSourcesCycloneDxRef)
	require.Contains(t, projectDependencies, mozillaCaDataCycloneDxRef)
}

func TestNormalizeSbomRejectsMissingInventoryModule(t *testing.T) {
	filename := t.TempDir() + "/artifact.spdx.json"
	require.NoError(t, gos.WriteFile(filename, []byte(`{
  "creationInfo":{"created":"now"},
  "packages":[
    {"SPDXID":"SPDXRef-Root","name":"artifact.tgz"},
    {"SPDXID":"SPDXRef-Project","name":"github.com/engity-com/bifroest","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/github.com/engity-com/bifroest"}]},
    {"SPDXID":"SPDXRef-Stdlib","name":"stdlib","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/stdlib@1.27.0"}]}
  ],
  "relationships":[{"spdxElementId":"SPDXRef-Stdlib","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-Project"}]
}`), 0644))

	err := normalizeSbom(filename, testSbomPlatform, buildArtifactTypeArchive, "artifact.tgz", "sha256:123", time.Time{}, testThirdPartyLicenseInventory())

	require.ErrorContains(t, err, "is missing from SBOM")
}

func testThirdPartyLicenseInventory() *thirdPartyLicenseInventory {
	return &thirdPartyLicenseInventory{modules: []thirdPartyLicenseModule{{
		names:             []string{"example.com/dependency"},
		version:           "v1.2.3",
		licenseExpression: "MIT",
	}}}
}

func jsonObjects(raw any) []map[string]any {
	values, _ := raw.([]any)
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if object, ok := value.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func jsonObjectWith(values []map[string]any, key, expected string) map[string]any {
	for _, value := range values {
		if value[key] == expected {
			return value
		}
	}
	return nil
}

func testCycloneDxLicense(component map[string]any) string {
	result, _ := cycloneDxLicenseExpression(component["licenses"])
	return result
}
