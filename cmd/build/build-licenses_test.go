package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	gos "os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/internal/build/images"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestReleaseLicenseFiles(t *testing.T) {
	root, expected := testReleaseLicenseRoot(t)

	actual, err := releaseLicenseFiles(root)

	require.NoError(t, err)
	require.Len(t, actual, len(expected))
	for _, license := range actual {
		content, err := gos.ReadFile(license.source)
		require.NoError(t, err)
		require.Equal(t, expected[license.name], string(content))
		require.NotContains(t, license.name, `\`)
	}
}

func TestReleaseLicenseFilesRequiresLicenseDirectory(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, gos.WriteFile(filepath.Join(root, "LICENSE"), []byte("project license"), 0644))

	_, err := releaseLicenseFiles(root)

	require.ErrorContains(t, err, "LICENSES")
}

func TestAddReleaseLicensesToArchives(t *testing.T) {
	root, expected := testReleaseLicenseRoot(t)
	timestamp := time.Date(2026, time.September, 12, 12, 0, 0, 0, time.UTC)

	t.Run("tgz", func(t *testing.T) {
		var target bytes.Buffer
		writer, err := (&buildArchive{}).newTgzWriter(timestamp, &target)
		require.NoError(t, err)
		require.NoError(t, addReleaseLicensesToArchive(root, writer))
		require.NoError(t, writer.Close())

		compressed, err := gzip.NewReader(bytes.NewReader(target.Bytes()))
		require.NoError(t, err)
		defer compressed.Close()
		require.Equal(t, expected, readTarFileContents(t, compressed))
	})

	t.Run("zip", func(t *testing.T) {
		var target bytes.Buffer
		writer, err := (&buildArchive{}).newZipWriter(timestamp, &target)
		require.NoError(t, err)
		require.NoError(t, addReleaseLicensesToArchive(root, writer))
		require.NoError(t, writer.Close())

		archive, err := zip.NewReader(bytes.NewReader(target.Bytes()), int64(target.Len()))
		require.NoError(t, err)
		actual := make(map[string]string, len(archive.File))
		for _, file := range archive.File {
			content, err := file.Open()
			require.NoError(t, err)
			raw, err := io.ReadAll(content)
			require.NoError(t, err)
			require.NoError(t, content.Close())
			actual[file.Name] = string(raw)
		}
		require.Equal(t, expected, actual)
	})
}

func TestReleaseLicenseImageItems(t *testing.T) {
	root, licenses := testReleaseLicenseRoot(t)
	tests := map[string]struct {
		os     sys.Os
		prefix string
	}{
		"linux": {
			os:     sys.OsLinux,
			prefix: "usr/share/licenses/bifroest/",
		},
		"windows": {
			os:     sys.OsWindows,
			prefix: "Files/Program Files/Engity/Bifroest/",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			items, err := releaseLicenseImageItems(root, tt.os)
			require.NoError(t, err)
			layer, err := images.NewTarLayer(common.Seq2ErrOf(items...), images.LayerOpts{
				Os:   tt.os,
				Id:   "release-licenses-" + name,
				Time: time.Date(2026, time.September, 12, 12, 0, 0, 0, time.UTC),
			})
			require.NoError(t, err)
			defer layer.Close()
			content, err := layer.Layer.Uncompressed()
			require.NoError(t, err)
			defer content.Close()

			expected := make(map[string]string, len(licenses))
			for license, value := range licenses {
				expected[tt.prefix+license] = value
			}
			require.Equal(t, expected, readTarFileContents(t, content))
		})
	}
}

func testReleaseLicenseRoot(t *testing.T) (string, map[string]string) {
	t.Helper()
	root := t.TempDir()
	expected := map[string]string{
		"LICENSE":                          "project license",
		"LICENSES/MIT.txt":                 "MIT license",
		"LICENSES/vendor/BSD-3-Clause.txt": "BSD license",
	}
	for name, content := range expected {
		filename := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, gos.MkdirAll(filepath.Dir(filename), 0755))
		require.NoError(t, gos.WriteFile(filename, []byte(content), 0644))
	}
	return root, expected
}

func readTarFileContents(t *testing.T, source io.Reader) map[string]string {
	t.Helper()
	result := make(map[string]string)
	reader := tar.NewReader(source)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return result
		}
		require.NoError(t, err)
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		require.NoError(t, err)
		result[header.Name] = string(content)
	}
}
