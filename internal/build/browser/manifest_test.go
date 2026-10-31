package browser

import (
	"bytes"
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
