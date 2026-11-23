package charts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func sourceChart() fstest.MapFS {
	return fstest.MapFS{
		"Chart.yaml":               {Data: []byte("apiVersion: v2\nname: bifroest\ntype: application\nversion: 0.0.0\nappVersion: 0.0.0\ndescription: Gateway\n")},
		"values.yaml":              {Data: []byte("message: unchanged\n")},
		"templates/configmap.yaml": {Data: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\ndata:\n  message: {{ .Values.message | quote }}\n")},
	}
}

func TestChartArchiveIsReproducibleAndDoesNotRenderTemplates(t *testing.T) {
	source := sourceChart()
	created := time.Unix(1700000000, 0)
	first, err := Build(t.Context(), source, "1.2.3-alpha1", created)
	require.NoError(t, err)
	second, err := Build(t.Context(), source, "1.2.3-alpha1", created)
	require.NoError(t, err)
	require.Equal(t, first.Data, second.Data)
	reader, err := gzip.NewReader(bytes.NewReader(first.Data))
	require.NoError(t, err)
	defer reader.Close()
	archive := tar.NewReader(reader)
	var names []string
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		names = append(names, header.Name)
		require.EqualValues(t, 0644, header.Mode)
		require.Equal(t, created, header.ModTime)
		raw, err := io.ReadAll(archive)
		require.NoError(t, err)
		if header.Name == "bifroest/Chart.yaml" {
			var meta map[string]any
			require.NoError(t, yaml.Unmarshal(raw, &meta))
			require.Equal(t, "1.2.3-alpha1", meta["version"])
			require.Equal(t, meta["version"], meta["appVersion"])
		} else {
			require.Equal(t, source[strings.TrimPrefix(header.Name, "bifroest/")].Data, raw)
		}
	}
	require.Equal(t, []string{"bifroest/Chart.yaml", "bifroest/templates/configmap.yaml", "bifroest/values.yaml"}, names)
	manifest, err := first.Image.Manifest()
	require.NoError(t, err)
	require.Equal(t, ConfigMediaType, manifest.Config.MediaType)
	require.Equal(t, LayerMediaType, manifest.Layers[0].MediaType)
	raw, err := first.Image.RawConfigFile()
	require.NoError(t, err)
	var meta map[string]any
	require.NoError(t, json.Unmarshal(raw, &meta))
	require.Equal(t, "1.2.3-alpha1", meta["version"])
}

func TestChartRejectsUnexpectedInputsAndNonSemanticVersions(t *testing.T) {
	for _, name := range []string{
		"secret.key", ".git/config", "templates/linked.yaml", "templates/private.key", "templates/private.pem",
		"templates/configmap.yaml.bak", "templates/configmap.yaml~", "templates/configmap.yaml.swp",
		"templates/unexpected.txt", "templates/nested/.env", "templates/nested/.private/secret.yaml",
		"templates/nested\\secret.yaml", "templates/new\nline.yaml",
	} {
		source := sourceChart()
		mode := fs.FileMode(0)
		if strings.Contains(name, "linked") {
			mode = fs.ModeSymlink
		}
		source[name] = &fstest.MapFile{Data: []byte("private"), Mode: mode}
		_, err := Build(t.Context(), source, "1.2.3", time.Time{})
		require.Error(t, err, name)
	}
	for _, version := range []string{"", "v1.2.3", "feature-branch", "1.2"} {
		_, err := Build(t.Context(), sourceChart(), version, time.Time{})
		require.Error(t, err, version)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Build(ctx, sourceChart(), "1.2.3", time.Time{})
	require.ErrorIs(t, err, context.Canceled)
}

func testChartTime() time.Time { return time.Unix(1700000000, 0) }

func chartArchiveFiles(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	defer reader.Close()
	archive := tar.NewReader(reader)
	files := make(map[string][]byte)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		require.EqualValues(t, tar.TypeReg, header.Typeflag)
		files[header.Name], err = io.ReadAll(archive)
		require.NoError(t, err)
	}
	return files
}

type guardedChartFS struct {
	fs.FS
	forbidden   map[string]bool
	ignoreOpens int
}

func (this *guardedChartFS) Open(name string) (fs.File, error) {
	if this.forbidden[name] {
		return nil, fmt.Errorf("excluded chart input %q must not be opened", name)
	}
	if name == ".helmignore" {
		this.ignoreOpens++
	}
	return this.FS.Open(name)
}

func TestChartExcludedFilesAreNeverReadOrPublished(t *testing.T) {
	source := sourceChart()
	ignore := []byte("templates/*.key\ntemplates/private.yaml\nlocal/\n*.bak\n.env*\n")
	source[".helmignore"] = &fstest.MapFile{Data: ignore}
	baseline, err := Build(t.Context(), source, "1.2.3", testChartTime())
	require.NoError(t, err)
	forbidden := map[string]bool{
		"templates/private.key":        true,
		"templates/private.yaml":       true,
		"templates/.hidden.yaml":       true,
		"templates/configmap.yaml.bak": true,
		".env.production":              true,
		"local":                        true,
		"local/private.key":            true,
	}
	for name := range forbidden {
		if name != "local" {
			source[name] = &fstest.MapFile{Data: []byte("SYNTHETIC-SECRET-NOT-A-REAL-KEY")}
		}
	}
	guarded := &guardedChartFS{FS: source, forbidden: forbidden}
	withPrivateFiles, err := Build(t.Context(), guarded, "1.2.3", testChartTime())
	require.NoError(t, err)
	require.Equal(t, 1, guarded.ignoreOpens, ".helmignore is checked and read only once")
	require.Equal(t, baseline.Data, withPrivateFiles.Data, "excluded inputs cannot change the published archive")
	files := chartArchiveFiles(t, withPrivateFiles.Data)
	require.Len(t, files, 4)
	require.Equal(t, ignore, files["bifroest/.helmignore"])
	for name := range forbidden {
		require.NotContains(t, files, "bifroest/"+name)
	}
}

func TestChartAllowsOnlyIntendedTemplateFileTypes(t *testing.T) {
	source := sourceChart()
	for _, name := range []string{"templates/nested/config.yml", "templates/_helpers.tpl", "templates/nested/_helpers.tpl", "templates/NOTES.txt"} {
		source[name] = &fstest.MapFile{Data: []byte("unchanged {{ .Release.Name }}")}
	}
	chart, err := Build(t.Context(), source, "1.2.3", testChartTime())
	require.NoError(t, err)
	files := chartArchiveFiles(t, chart.Data)
	for name, file := range source {
		if name != "Chart.yaml" {
			require.Equal(t, file.Data, files["bifroest/"+name])
		}
	}
}

func TestChartRejectsLinksAndSpecialFilesEvenWhenIgnored(t *testing.T) {
	for _, mode := range []fs.FileMode{fs.ModeSymlink, fs.ModeNamedPipe, fs.ModeSocket, fs.ModeDevice} {
		t.Run(mode.String(), func(t *testing.T) {
			source := sourceChart()
			source[".helmignore"] = &fstest.MapFile{Data: []byte("*.yaml\n")}
			source["templates/linked.yaml"] = &fstest.MapFile{Data: []byte("private"), Mode: mode}
			_, err := Build(t.Context(), source, "1.2.3", testChartTime())
			require.Error(t, err)
		})
	}
}

func TestChartRejectsMissingOrInvalidRequiredInputsAfterIgnore(t *testing.T) {
	for name, ignore := range map[string]string{
		"ignored-chart":   "Chart.yaml\n",
		"ignored-values":  "values.yaml\n",
		"invalid-pattern": "[\n",
	} {
		t.Run(name, func(t *testing.T) {
			source := sourceChart()
			source[".helmignore"] = &fstest.MapFile{Data: []byte(ignore)}
			_, err := Build(t.Context(), source, "1.2.3", testChartTime())
			require.Error(t, err)
		})
	}
}
