package images

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"
	"testing/fstest"
	"time"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/stretchr/testify/require"
)

func TestRegularBifroestImageKeepsEntrypointRunDefaultAndSystemLayout(t *testing.T) {
	p := bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}
	request, err := BifroestBuildRequest(p, "bifroest")
	require.NoError(t, err)
	require.Equal(t, ImageScratch, request.From)
	require.Equal(t, []string{sys.BifroestOciBinaryFileLocation(sys.OsLinux)}, request.EntryPoint)
	require.Equal(t, []string{"run"}, request.Cmd)
	require.Equal(t, map[string]struct{}{"22/tcp": {}}, request.ExposedPorts)
	require.True(t, request.AddDummyConfiguration)
	require.True(t, request.AddSkeletonStructure)
	request.BifroestBinarySourceFs = fstest.MapFS{"bifroest": {Data: []byte("actual binary bytes"), Mode: 0755}}
	request.Time = time.Unix(1234, 0).UTC()
	image, err := Build(t.Context(), request)
	require.NoError(t, err)
	defer func() { require.NoError(t, image.Close()) }()
	config, err := image.ConfigFile()
	require.NoError(t, err)
	require.Equal(t, request.EntryPoint, config.Config.Entrypoint)
	require.Equal(t, []string{"run"}, config.Config.Cmd)
	require.Equal(t, "linux", config.OS)
	require.Equal(t, "amd64", config.Architecture)
	layers, err := image.Layers()
	require.NoError(t, err)
	require.Len(t, layers, 1)
	stream, err := layers[0].Uncompressed()
	require.NoError(t, err)
	defer func() { require.NoError(t, stream.Close()) }()
	contents := map[string][]byte{}
	reader := tar.NewReader(stream)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(reader)
		require.NoError(t, err)
		contents[header.Name] = data
	}
	for _, path := range []string{"etc/passwd", "etc/group", "etc/shadow", "etc/engity/bifroest/configuration.yaml"} {
		require.Contains(t, contents, path)
	}
	path := sys.BifroestOciBinaryFileLocation(sys.OsLinux)[1:]
	require.True(t, bytes.Equal([]byte("actual binary bytes"), contents[path]))
}

func TestRegularImageFactoryUsesExistingPlatformBaseSelection(t *testing.T) {
	for _, platform := range []bib.Platform{
		{Os: sys.OsLinux, Arch: sys.ArchArm64, Edition: sys.EditionGeneric},
		{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionExtended},
		{Os: sys.OsWindows, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric},
	} {
		request, err := BifroestBuildRequest(platform, "binary")
		require.NoError(t, err)
		base, err := platform.SourceOciImage()
		require.NoError(t, err)
		require.Equal(t, base, request.From)
		require.Equal(t, []string{sys.BifroestOciBinaryFileLocation(platform.Os)}, request.EntryPoint)
		require.Equal(t, []string{"run"}, request.Cmd)
	}
}
