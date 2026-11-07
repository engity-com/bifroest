package webui

import (
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func assetFixture(t *testing.T) (*Assets, string) {
	t.Helper()
	directory := t.TempDir()
	root, err := openPublicRoot(directory)
	require.NoError(t, err)
	assets := &Assets{overlay: root, embedded: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<html><head><link rel="stylesheet" href="/_bifroest/files/assets/main.css"></head><body><div id="root"></div><script type="module" src="/_bifroest/files/assets/main.js"></script></body></html>`)}, "assets/main.js": &fstest.MapFile{Data: []byte("embedded-js")}, "assets/main.css": &fstest.MapFile{Data: []byte("embedded-css")}}}
	t.Cleanup(func() { require.NoError(t, assets.Close()) })
	return assets, directory
}

func TestPublicAssetsUsePerFileOverlayWithoutCleaningAliases(t *testing.T) {
	assets, directory := assetFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(directory, "assets"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "assets", "main.js"), []byte("overlay-js"), 0644))
	data, kind, err := assets.Resource(Prefix + "assets/main.js")
	require.NoError(t, err)
	require.Equal(t, "overlay-js", string(data))
	require.Contains(t, kind, "javascript")
	data, _, err = assets.Resource(Prefix + "assets/main.css")
	require.NoError(t, err)
	require.Equal(t, "embedded-css", string(data))
	for _, name := range []string{"../private", "assets/../main.js", "assets//main.js", "/assets/main.js", "assets/.key", "assets/main.js.", "assets/CON.js", "assets/key:secret", "assets/%2e%2e/private", "assets\\private"} {
		_, err := assets.Read(name)
		require.ErrorIs(t, err, ErrAsset, name)
	}
	_, _, err = assets.Resource("/_bifroest/api/v1/login/password")
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, _, err = assets.Resource(Prefix + "index.html")
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, _, err = assets.Resource(Prefix + "assets/missing.js")
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestPublicAssetsRejectSymlinksHardlinksDirectoriesAndOversizeWithoutFallback(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "directory", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			assets, directory := assetFixture(t)
			require.NoError(t, os.Mkdir(filepath.Join(directory, "assets"), 0755))
			target := filepath.Join(directory, "assets", "main.js")
			switch mode {
			case "symlink", "hardlink":
				private := filepath.Join(t.TempDir(), "private")
				require.NoError(t, os.WriteFile(private, []byte("must-not-leak"), 0600))
				var err error
				if mode == "symlink" {
					err = os.Symlink(private, target)
				} else {
					err = os.Link(private, target)
				}
				if err != nil {
					t.Skipf("host cannot create %s: %v", mode, err)
				}
			case "directory":
				require.NoError(t, os.Mkdir(target, 0755))
			case "oversize":
				file, err := os.Create(target)
				require.NoError(t, err)
				require.NoError(t, file.Truncate(maxFile+1))
				require.NoError(t, file.Close())
			}
			data, _, err := assets.Resource(Prefix + "assets/main.js")
			require.Error(t, err)
			require.Empty(t, data, "never return embedded fallback or private bytes for an existing unsafe overlay")
		})
	}
}

func TestPublicDocumentNoncesCustomizationOrderAndMissingHeadBody(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "index.html"), []byte(`<div id="root"></div><script src="/_bifroest/files/assets/main.js"></script><meta name="bifroest-nonce" content="old">`), 0644))
	css1, css2, js := filepath.Join(directory, "first.css"), filepath.Join(directory, "second.css"), filepath.Join(directory, "last.js")
	for file, body := range map[string]string{css1: "first", css2: "second", js: "custom"} {
		require.NoError(t, os.WriteFile(file, []byte(body), 0644))
	}
	assets, err := New(&configuration.Http{AssetsDirectory: directory, CustomCss: []string{css1, css2}, CustomJs: []string{js}, CustomHtmlHead: `<style>body{color:red}</style><script>window.trusted=true</script><script src="https://remote.example/no.js" nonce="bad"></script>`, CustomHtmlBody: `<p>last trusted body content</p>`})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, assets.Close()) })
	data, nonce, err := assets.Document()
	require.NoError(t, err)
	raw, err := base64.StdEncoding.Strict().DecodeString(nonce)
	require.NoError(t, err)
	require.Len(t, raw, 32)
	text := string(data)
	require.Contains(t, text, "<head>")
	require.Contains(t, text, "<body>")
	require.NotContains(t, text, `content="old"`)
	require.NotContains(t, text, `nonce="bad"`)
	require.Contains(t, text, `<style nonce="`+nonce+`">`)
	require.Contains(t, text, `<script nonce="`+nonce+`">window.trusted`)
	require.Contains(t, text, `<script src="https://remote.example/no.js"></script>`)
	require.Less(t, strings.Index(text, "css/0.css"), strings.Index(text, "css/1.css"))
	require.Less(t, strings.Index(text, "assets/main.js"), strings.Index(text, "custom/js/0.js"))
	require.Less(t, strings.Index(text, "custom/js/0.js"), strings.Index(text, "last trusted body"))
	_, second, err := assets.Document()
	require.NoError(t, err)
	require.NotEqual(t, nonce, second)
	data, kind, err := assets.Resource(CustomPrefix + "css/1.css")
	require.NoError(t, err)
	require.Equal(t, "second", string(data))
	require.Contains(t, kind, "text/css")
	for _, name := range []string{"css/01.css", "js/-1.js", "js/0.css", "css/2.css"} {
		_, _, err := assets.Resource(CustomPrefix + name)
		require.ErrorIs(t, err, fs.ErrNotExist)
	}
}

func TestPublicAssetsRejectLinkedParentAndRemainAnchoredToOpenedRoot(t *testing.T) {
	assets, directory := assetFixture(t)
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "main.js"), []byte("private-parent"), 0600))
	if err := os.Symlink(outside, filepath.Join(directory, "assets")); err != nil {
		t.Skipf("host cannot create symlinks: %v", err)
	}
	data, _, err := assets.Resource(Prefix + "assets/main.js")
	require.Error(t, err)
	require.Empty(t, data)
	_, err = openPublicRoot(filepath.Join(directory, "assets"))
	require.ErrorIs(t, err, ErrAsset)
}
