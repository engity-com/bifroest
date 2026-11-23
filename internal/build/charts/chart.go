// Package charts packages Helm charts and combines them with existing OCI images.
// It does not render templates or require Helm or its SDK.
package charts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"gopkg.in/yaml.v3"
)

const ConfigMediaType types.MediaType = "application/vnd.cncf.helm.config.v1+json"
const LayerMediaType types.MediaType = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

type Package struct {
	Name    string
	Version string
	Data    []byte
	Image   v1.Image
}

// Build stamps both versions and produces a deterministic, bounded chart archive.
// It honors .helmignore and accepts only chart-owned files; encountered links and
// non-ignored unexpected inputs fail.
func Build(ctx context.Context, source fs.FS, version string, created time.Time) (*Package, error) {
	if _, err := semver.StrictNewVersion(version); err != nil {
		return nil, fmt.Errorf("chart version must be a canonical semantic version: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ignores, rawIgnore, err := readChartIgnore(source)
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte)
	var total int64
	if err := fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("linked chart input %q is forbidden", name)
		}
		if strings.ContainsAny(name, "\\\x00\r\n") || (!entry.IsDir() && !entry.Type().IsRegular()) {
			return fmt.Errorf("unexpected chart input %q", name)
		}
		if chartInputIgnored(ignores, name, entry.IsDir()) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if name != "." && name != "templates" && (!strings.HasPrefix(name, "templates/") || hiddenChartPath(name)) {
				return fmt.Errorf("unexpected chart directory %q", name)
			}
			return nil
		}
		if !allowedChartInput(name) || len(files) >= 128 {
			return fmt.Errorf("unexpected chart input %q", name)
		}
		raw := rawIgnore
		if name != ".helmignore" {
			var err error
			raw, err = readChartFile(source, name, 8<<20)
			if err != nil {
				return err
			}
		}
		total += int64(len(raw))
		if total > 32<<20 {
			return fmt.Errorf("chart source exceeds size limit")
		}
		files[name] = raw
		return nil
	}); err != nil {
		return nil, err
	}
	var metadata map[string]any
	if err := yaml.Unmarshal(files["Chart.yaml"], &metadata); err != nil {
		return nil, fmt.Errorf("invalid Chart.yaml: %w", err)
	}
	if metadata["apiVersion"] != "v2" || metadata["name"] != "bifroest" || metadata["type"] != "application" {
		return nil, fmt.Errorf("expected an apiVersion v2 application chart named bifroest")
	}
	if _, ok := files["values.yaml"]; !ok {
		return nil, fmt.Errorf("chart is missing values.yaml")
	}
	metadata["version"], metadata["appVersion"] = version, version
	rawMetadata, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	files["Chart.yaml"], err = yaml.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	var archive bytes.Buffer
	compressed, err := gzip.NewWriterLevel(&archive, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	writer := tar.NewWriter(compressed)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header := &tar.Header{Name: path.Join("bifroest", name), Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(files[name])), ModTime: created.UTC().Truncate(time.Second)}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := writer.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if err := compressed.Close(); err != nil {
		return nil, err
	}
	data := archive.Bytes()
	layer := static.NewLayer(data, LayerMediaType)
	digest, err := layer.Digest()
	if err != nil {
		return nil, err
	}
	configDigest, configSize, err := v1.SHA256(bytes.NewReader(rawMetadata))
	if err != nil {
		return nil, err
	}
	manifest, err := json.Marshal(v1.Manifest{
		SchemaVersion: 2, MediaType: types.OCIManifestSchema1, ArtifactType: string(ConfigMediaType),
		Config:      v1.Descriptor{MediaType: ConfigMediaType, Digest: configDigest, Size: configSize},
		Layers:      []v1.Descriptor{{MediaType: LayerMediaType, Digest: digest, Size: int64(len(data))}},
		Annotations: map[string]string{"org.opencontainers.image.title": "bifroest", "org.opencontainers.image.version": version},
	})
	if err != nil {
		return nil, err
	}
	image, err := partial.CompressedToImage(&artifact{config: rawMetadata, manifest: manifest, layer: layer})
	if err != nil {
		return nil, err
	}
	return &Package{Name: "bifroest", Version: version, Data: data, Image: image}, nil
}

func allowedChartInput(name string) bool {
	if slices.Contains([]string{"Chart.yaml", "values.yaml", "values.schema.json", "README.md", "LICENSE", ".helmignore", "templates/NOTES.txt"}, name) {
		return true
	}
	return strings.HasPrefix(name, "templates/") && !hiddenChartPath(name) && slices.Contains([]string{".yaml", ".yml", ".tpl"}, path.Ext(name))
}

func hiddenChartPath(name string) bool {
	return slices.ContainsFunc(strings.Split(name, "/"), func(part string) bool { return strings.HasPrefix(part, ".") })
}

// Combine retains the existing runnable platform descriptors. The chart has no
// runnable platform and therefore cannot replace an OS/architecture match.
func Combine(images v1.ImageIndex, chart v1.Image) (v1.ImageIndex, error) {
	descriptor, err := partial.Descriptor(chart)
	if err != nil {
		return nil, err
	}
	descriptor.Platform = &v1.Platform{OS: "unknown", Architecture: "unknown"}
	descriptor.ArtifactType = string(ConfigMediaType)
	return mutate.AppendManifests(mutate.IndexMediaType(images, types.OCIImageIndex), mutate.IndexAddendum{Add: chart, Descriptor: *descriptor}), nil
}

type artifact struct {
	config, manifest []byte
	layer            v1.Layer
}

func (this *artifact) RawConfigFile() ([]byte, error)      { return slices.Clone(this.config), nil }
func (this *artifact) RawManifest() ([]byte, error)        { return slices.Clone(this.manifest), nil }
func (this *artifact) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }
func (this *artifact) LayerByDigest(hash v1.Hash) (partial.CompressedLayer, error) {
	digest, err := this.layer.Digest()
	if err != nil {
		return nil, err
	}
	if hash != digest {
		return nil, fmt.Errorf("chart layer %s is unavailable", hash)
	}
	return this.layer, nil
}
