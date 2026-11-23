package charts

import (
	"io"
	"log"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

func TestCombinedTagRetainsRunnablePlatformImages(t *testing.T) {
	chart, err := Build(t.Context(), os.DirFS(projectSource()), "1.2.3", time.Unix(1700000000, 0))
	require.NoError(t, err)
	var images []mutate.IndexAddendum
	wanted := make(map[string]v1.Hash)
	for _, arch := range []string{"amd64", "arm64"} {
		image, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: arch})
		require.NoError(t, err)
		if arch == "arm64" {
			image = mutate.MediaType(image, types.OCIManifestSchema1)
			image = mutate.ConfigMediaType(image, types.OCIConfigJSON)
		}
		descriptor, err := partial.Descriptor(image)
		require.NoError(t, err)
		descriptor.Platform = &v1.Platform{OS: "linux", Architecture: arch}
		images = append(images, mutate.IndexAddendum{Add: image, Descriptor: *descriptor})
		wanted[arch] = descriptor.Digest
	}
	combined, err := Combine(mutate.AppendManifests(empty.Index, images...), chart.Image)
	require.NoError(t, err)
	mediaType, err := combined.MediaType()
	require.NoError(t, err)
	require.Equal(t, types.OCIImageIndex, mediaType)
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	ref, err := name.NewTag(strings.TrimPrefix(server.URL, "http://")+"/engity-com/bifroest:1.2.3", name.Insecure)
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(ref, combined, remote.WithContext(t.Context())))
	for arch, expected := range wanted {
		image, err := remote.Image(ref, remote.WithContext(t.Context()), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: arch}))
		require.NoError(t, err)
		digest, err := image.Digest()
		require.NoError(t, err)
		require.Equal(t, expected, digest)
	}
}

func TestCombinedTagWithRealHelmConsumer(t *testing.T) {
	helm := testHelm(t)
	chart, err := Build(t.Context(), os.DirFS(projectSource()), "1.2.3", time.Unix(1700000000, 0))
	require.NoError(t, err)
	image := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	image = mutate.ConfigMediaType(image, types.OCIConfigJSON)
	descriptor, err := partial.Descriptor(image)
	require.NoError(t, err)
	descriptor.Platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
	images := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: image, Descriptor: *descriptor})
	combined, err := Combine(images, chart.Image)
	require.NoError(t, err)
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	repository := strings.TrimPrefix(server.URL, "http://") + "/engity-com/bifroest"
	ref, err := name.NewTag(repository+":1.2.3", name.Insecure)
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(ref, combined, remote.WithContext(t.Context())))
	directory := t.TempDir()
	command := exec.CommandContext(t.Context(), helm, "pull", "oci://"+repository, "--version", "1.2.3", "--plain-http", "--destination", directory)
	command.Env = append(os.Environ(), "HELM_CONFIG_HOME="+directory, "HELM_CACHE_HOME="+directory, "HELM_DATA_HOME="+directory, "DOCKER_CONFIG="+directory)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	got, err := os.ReadFile(filepath.Join(directory, "bifroest-1.2.3.tgz"))
	require.NoError(t, err)
	require.Equal(t, chart.Data, got)
	command = exec.CommandContext(t.Context(), helm, "template", "proof", "oci://"+repository, "--version", "1.2.3", "--plain-http")
	command.Env = append(os.Environ(), "HELM_CONFIG_HOME="+directory, "HELM_CACHE_HOME="+directory, "HELM_DATA_HOME="+directory, "DOCKER_CONFIG="+directory)
	output, err = command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.Contains(t, string(output), "kind: StatefulSet")
	require.Contains(t, string(output), "ghcr.io/engity-com/bifroest:1.2.3")
}
