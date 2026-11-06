package browser

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T) (*Manifest, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/minimal.json")
	require.NoError(t, err)
	m, err := Decode(raw)
	require.NoError(t, err)
	return m, raw
}

func TestBrowserBuildManifestBoundsAndExactInventory(t *testing.T) {
	m, raw := fixture(t)
	root := fstest.MapFS{Filename: &fstest.MapFile{Data: raw}}
	for _, file := range m.Assets {
		root[file.Name] = &fstest.MapFile{Data: []byte{}}
	}
	require.NoError(t, m.VerifyAssets(root))
	root["extra.js"] = &fstest.MapFile{Data: []byte("unlisted")}
	require.Error(t, m.VerifyAssets(root))
	delete(root, "extra.js")
	root["index.html"].Data = []byte("tampered")
	require.Error(t, m.VerifyAssets(root))
	root["index.html"].Data = []byte{}
	delete(root, "browser-key-worker.js")
	require.Error(t, m.VerifyAssets(root))
	for _, malformed := range [][]byte{append(bytes.Clone(raw), []byte(`{}`)...), bytes.Replace(raw, []byte(`"bun": "1.4.4"`), []byte(`"unknown": true, "bun": "1.4.4"`), 1), bytes.Repeat([]byte("x"), MaximumManifestBytes+1)} {
		_, err := Decode(malformed)
		require.Error(t, err)
	}
}

func TestBrowserManifestRejectsUnsupportedAndAmbiguousComponents(t *testing.T) {
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.Assets = append(m.Assets, m.Assets[0]) },
		func(m *Manifest) { m.Inputs[0].Name = "../outside" },
		func(m *Manifest) { m.Assets[0].Bytes = 8<<20 + 1 },
		func(m *Manifest) { m.Components[0].Integrity = "sha512-invalid" },
		func(m *Manifest) { m.Components[0].License = "unknown" },
		func(m *Manifest) { m.Components = append(m.Components, m.Components[0]) },
		func(m *Manifest) { m.Components[0].Artifacts = []string{"outside.wasm"} },
		func(m *Manifest) { m.Scope = "signed provenance" },
		func(m *Manifest) { m.Node = "99.0.0" },
		func(m *Manifest) { m.LocalBundlingPatches = nil },
	} {
		m, _ := fixture(t)
		change(m)
		raw, err := json.Marshal(m)
		require.NoError(t, err)
		_, err = Decode(raw)
		require.Error(t, err)
	}
}

func TestVendoredSvgKeepsStrictReviewedProvenanceAndExactSourceBinding(t *testing.T) {
	for _, mutate := range []func(*Manifest, *Component){
		nil,
		func(_ *Manifest, c *Component) { c.Source = "https://unreviewed.invalid/icon" },
		func(_ *Manifest, c *Component) { c.UpstreamPathSHA256 = "a" + c.UpstreamPathSHA256[1:] },
		func(_ *Manifest, c *Component) { c.Name = "Other icon" },
		func(_ *Manifest, c *Component) { c.Version = "invented-version" },
		func(_ *Manifest, c *Component) { c.Integrity = "sha256-invalid" },
		func(m *Manifest, _ *Component) { m.Inputs = m.Inputs[:len(m.Inputs)-1] },
		func(_ *Manifest, c *Component) { c.Ecosystem = "npm"; c.Version = "1.0.0" },
	} {
		m, _ := fixture(t)
		digest := bytes.Repeat([]byte{3}, 32)
		m.Inputs = append(m.Inputs, File{Name: "web/src/ui/LeftPanelCloseIcon.tsx", Bytes: 1024, SHA256: hex.EncodeToString(digest)})
		c := Component{Ecosystem: "vendored-svg", Name: "Google Material Symbols / left_panel_close", Version: "24px outlined", License: "Apache-2.0", Integrity: "sha256-" + base64.StdEncoding.EncodeToString(digest), LicenseTextSource: "vendored SVG", Artifacts: []string{"browser-ui"}, Source: "https://github.com/google/material-design-icons/tree/master/symbols/web/left_panel_close", UpstreamPathSHA256: "909577477a457f6902f6000398429358f32e11333146c050e80bb8abd9e4946f"}
		if mutate != nil {
			mutate(m, &c)
		}
		m.Components = append(m.Components, c)
		raw, err := json.Marshal(m)
		require.NoError(t, err)
		_, err = Decode(raw)
		if mutate == nil {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}
