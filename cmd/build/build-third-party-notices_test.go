package main

import (
	"bytes"
	gos "os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestReadThirdPartyLicensePolicy(t *testing.T) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)

	require.NoError(t, err)
	require.Equal(t, 2, policy.SchemaVersion)
	require.Equal(t, thirdPartyLicenseAllowed, policy.licenseDecision("MIT"))
	require.Equal(t, thirdPartyLicenseManualReview, policy.licenseDecision("GPL-3.0-only"))
	require.Equal(t, "github.com/moby/moby", canonicalModuleMap(policy)["github.com/docker/docker"])
}

func TestReadThirdPartyLicensePolicyRejectsOverlappingDecisions(t *testing.T) {
	_, err := readThirdPartyLicensePolicy([]byte(`{
		"schemaVersion": 2,
		"allowedLicenses": ["MIT"],
		"rejectedLicenses": ["MIT"],
		"manualReviewLicenses": [],
		"unclassifiedLicenseDecision": "manual-review",
		"canonicalComponents": []
	}`))

	require.ErrorContains(t, err, `license "MIT" is classified as both allowed and rejected`)
}

func TestReadThirdPartyLicensePolicyRequiresManualReviewByDefault(t *testing.T) {
	_, err := readThirdPartyLicensePolicy([]byte(`{
		"schemaVersion": 2,
		"allowedLicenses": ["MIT"],
		"rejectedLicenses": [],
		"manualReviewLicenses": [],
		"unclassifiedLicenseDecision": "allowed",
		"canonicalComponents": []
	}`))

	require.ErrorContains(t, err, `must classify unlisted licenses as "manual-review"`)
}

func TestParseThirdPartyLicenseRecords(t *testing.T) {
	raw := []byte("\n\"example.com/library\"\t\"v1.2.3\"\t\"MIT\"\t\"Copyright \\\"Example\\\"\\r\\n\"\n")

	records, err := parseThirdPartyLicenseRecords(raw)

	require.NoError(t, err)
	require.Equal(t, []thirdPartyLicenseRecord{{
		Library: "example.com/library",
		Version: "v1.2.3",
		License: "MIT",
		Text:    "Copyright \"Example\"\n",
	}}, records)
}

func TestReconcileThirdPartyComponentsCanonicalizesMoby(t *testing.T) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	require.NoError(t, err)
	modules := []*thirdPartyModule{
		{matches: []string{"github.com/docker/docker", "github.com/moby/moby"}, component: "github.com/moby/moby", version: "v28.5.2+incompatible"},
		{matches: []string{"github.com/moby/moby/api"}, component: "github.com/moby/moby", version: "v1.56.0"},
	}
	records := []thirdPartyLicenseRecord{
		{Library: "github.com/moby/moby/api/types", Version: "v1.56.0", License: "Apache-2.0", Text: "api license\n"},
		{Library: "github.com/docker/docker", Version: "v28.5.2", License: "Apache-2.0", Text: "moby license\n"},
	}
	saved := t.TempDir()
	testWriteFile(t, saved, "github.com/docker/docker/NOTICE", "moby notice\r\n")

	components, err := reconcileThirdPartyComponents(modules, records, saved, policy)

	require.NoError(t, err)
	require.Len(t, components, 1)
	require.Equal(t, "github.com/moby/moby", components[0].name)
	require.Contains(t, components[0].libraries, "github.com/moby/moby")
	require.NotContains(t, components[0].libraries, "github.com/docker/docker")
	notices := make([]thirdPartyNotice, 0, len(components[0].notices))
	for _, notice := range components[0].notices {
		notices = append(notices, notice)
	}
	require.Equal(t, "github.com/moby/moby/NOTICE", notices[0].name)
	require.Equal(t, "moby notice\n", notices[0].text)

	info := &debug.BuildInfo{GoVersion: goToolchainVersion}
	platform := bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}
	var first bytes.Buffer
	require.NoError(t, renderThirdPartyNotices(&first, platform, info, components))
	require.NotContains(t, first.String(), "github.com/docker/docker")
	require.Contains(t, first.String(), "Component: github.com/moby/moby")

	slicesReversed := []thirdPartyComponent{components[0]}
	var second bytes.Buffer
	require.NoError(t, renderThirdPartyNotices(&second, platform, info, slicesReversed))
	require.Equal(t, first.Bytes(), second.Bytes())
}

func TestReconcileThirdPartyComponentsRejectsVersionMismatch(t *testing.T) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	require.NoError(t, err)
	modules := []*thirdPartyModule{{matches: []string{"example.com/library"}, component: "example.com/library", version: "v1.0.0"}}
	records := []thirdPartyLicenseRecord{{Library: "example.com/library", Version: "v2.0.0", License: "MIT", Text: "license\n"}}

	_, err = reconcileThirdPartyComponents(modules, records, t.TempDir(), policy)

	require.ErrorContains(t, err, "reports version")
}

func TestReconcileThirdPartyComponentsEnforcesLicenseDecision(t *testing.T) {
	policy := thirdPartyLicensePolicy{
		AllowedLicenses:             []string{"MIT"},
		RejectedLicenses:            []string{"GPL-3.0-only"},
		ManualReviewLicenses:        []string{"MPL-2.0"},
		UnclassifiedLicenseDecision: string(thirdPartyLicenseManualReview),
	}
	modules := []*thirdPartyModule{{matches: []string{"example.com/library"}, component: "example.com/library", version: "v1.0.0"}}

	tests := []struct {
		name    string
		license string
		error   string
	}{
		{name: "rejected", license: "GPL-3.0-only", error: "is rejected by policy"},
		{name: "explicit manual review", license: "MPL-2.0", error: "requires manual review"},
		{name: "unclassified", license: "EPL-2.0", error: "requires manual review"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			records := []thirdPartyLicenseRecord{{Library: "example.com/library", Version: "v1.0.0", License: test.license, Text: "license\n"}}

			_, err := reconcileThirdPartyComponents(modules, records, t.TempDir(), policy)

			require.ErrorContains(t, err, test.error)
		})
	}
}

func TestThirdPartyModulesUsesReplacementAsCanonicalComponent(t *testing.T) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	require.NoError(t, err)
	info := &debug.BuildInfo{
		Path:      projectModule + "/cmd/bifroest",
		GoVersion: goToolchainVersion,
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"},
			{Key: "GOARCH", Value: "amd64"},
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "GOAMD64", Value: "v1"},
		},
		Deps: []*debug.Module{{
			Path:    "github.com/docker/docker",
			Version: "v0.0.0",
			Replace: &debug.Module{Path: "github.com/moby/moby", Version: "v28.5.2+incompatible"},
		}},
	}
	platform := bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}

	modules, err := thirdPartyModules(info, platform, policy)

	require.NoError(t, err)
	require.Len(t, modules, 1)
	require.Equal(t, "github.com/moby/moby", modules[0].component)
	require.Equal(t, "v28.5.2+incompatible", modules[0].version)
	require.Equal(t, []string{"github.com/docker/docker", "github.com/moby/moby"}, modules[0].matches)
}

func TestThirdPartyModulesRejectsWrongArmVariant(t *testing.T) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	require.NoError(t, err)
	info := &debug.BuildInfo{
		Path:      projectModule + "/cmd/bifroest",
		GoVersion: goToolchainVersion,
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"},
			{Key: "GOARCH", Value: "arm"},
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "GOARM", Value: "6"},
		},
	}
	platform := bib.Platform{Os: sys.OsLinux, Arch: sys.ArchArmV7, Edition: sys.EditionGeneric}

	_, err = thirdPartyModules(info, platform, policy)

	require.ErrorContains(t, err, "GOARM")
}

func TestReconcileThirdPartyComponentsCombinesLicenseNamesForSameText(t *testing.T) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	require.NoError(t, err)
	modules := []*thirdPartyModule{{matches: []string{"example.com/library"}, component: "example.com/library", version: "v1.0.0"}}
	records := []thirdPartyLicenseRecord{
		{Library: "example.com/library", Version: "v1.0.0", License: "Apache-2.0", Text: "combined license text\n"},
		{Library: "example.com/library", Version: "v1.0.0", License: "MIT", Text: "combined license text\n"},
	}

	components, err := reconcileThirdPartyComponents(modules, records, t.TempDir(), policy)

	require.NoError(t, err)
	require.Len(t, components, 1)
	require.Len(t, components[0].licenses, 1)
	for _, license := range components[0].licenses {
		require.Equal(t, []string{"Apache-2.0", "MIT"}, sortedSet(license.licenses))
	}
	inventory, err := newThirdPartyLicenseInventory(modules)
	require.NoError(t, err)
	require.Equal(t, "Apache-2.0 AND MIT", inventory.modules[0].licenseExpression)
}

func testWriteFile(t *testing.T, root, name, content string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	require.NoError(t, gos.MkdirAll(filepath.Dir(filename), 0755))
	require.NoError(t, gos.WriteFile(filename, []byte(content), 0644))
}
