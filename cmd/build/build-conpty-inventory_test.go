package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/conpty"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestConptyNoticesRequireTheActualPinnedEmbeddedPayloads(t *testing.T) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	require.NoError(t, err)
	source := os.DirFS(filepath.Join("..", "..", "internal", "conpty"))
	var binary []byte
	for _, payload := range conpty.Payloads {
		raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "conpty", payload.Filename()))
		require.NoError(t, err)
		binary = append(binary, raw...)
	}
	path := filepath.Join(t.TempDir(), "binary.exe")
	require.NoError(t, os.WriteFile(path, binary, 0600))
	artifact := &buildArtifact{Platform: &bib.Platform{Os: sys.OsWindows}, filepath: path}
	var notice bytes.Buffer
	require.NoError(t, appendConptyNotices(artifact, source, &notice, policy))
	require.ErrorContains(t, appendConptyNotices(artifact, source, &bytes.Buffer{}, thirdPartyLicensePolicy{}), "release license policy")
	require.Contains(t, notice.String(), conpty.Name+" "+conpty.Version)
	require.Contains(t, notice.String(), conpty.License)
	for _, payload := range conpty.Payloads {
		require.Contains(t, notice.String(), payload.SHA256)
	}
	require.NoError(t, os.WriteFile(path, binary[:len(binary)-1], 0600))
	require.ErrorContains(t, appendConptyNotices(artifact, source, &bytes.Buffer{}, policy), "does not embed pinned ConPTY")
	require.Error(t, appendConptyNotices(artifact, fstest.MapFS{}, &bytes.Buffer{}, policy))
	artifact.Os = sys.OsLinux
	var linuxNotice bytes.Buffer
	require.NoError(t, appendConptyNotices(artifact, fstest.MapFS{}, &linuxNotice, policy))
	require.Empty(t, linuxNotice.String(), "non-Windows distributions must not claim native Windows resources")
}

func TestConptySbomInventoriesSubsetAndDLLDigestsIdempotently(t *testing.T) {
	for _, format := range []string{"spdx-json@2.3", "cyclonedx-json@1.6"} {
		t.Run(format, func(t *testing.T) {
			document := map[string]any{
				"packages":   []any{map[string]any{"SPDXID": "root", "name": "artifact"}},
				"metadata":   map[string]any{"component": map[string]any{"bom-ref": "root"}},
				"components": []any{},
			}
			before, err := json.Marshal(document)
			require.NoError(t, err)
			require.NoError(t, enrichConptySbom(document, format, "artifact", &thirdPartyLicenseInventory{}))
			unchanged, err := json.Marshal(document)
			require.NoError(t, err)
			require.Equal(t, before, unchanged)
			inventory := &thirdPartyLicenseInventory{conPTY: true}
			require.NoError(t, enrichConptySbom(document, format, "artifact", inventory))
			first, err := json.Marshal(document)
			require.NoError(t, err)
			require.NoError(t, enrichConptySbom(document, format, "artifact", inventory))
			second, err := json.Marshal(document)
			require.NoError(t, err)
			require.Equal(t, first, second)
			require.Contains(t, string(first), "pkg:nuget/"+conpty.Name+"@"+conpty.Version)
			require.Contains(t, string(first), "OpenConsole.exe is not shipped")
			for _, payload := range conpty.Payloads {
				require.Contains(t, string(first), payload.SHA256)
			}
			var conflicted map[string]any
			require.NoError(t, json.Unmarshal(first, &conflicted))
			if format == "spdx-json@2.3" {
				conflicted["packages"].([]any)[1].(map[string]any)["versionInfo"] = "wrong"
			} else {
				conflicted["components"].([]any)[0].(map[string]any)["version"] = "wrong"
			}
			require.ErrorContains(t, enrichConptySbom(conflicted, format, "artifact", inventory), "conflicting SBOM")
		})
	}
}
