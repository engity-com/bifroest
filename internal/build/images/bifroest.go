package images

import (
	"fmt"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

// BifroestBuildRequest is the regular distribution image layout. Callers supply
// release-specific annotations, time and license/inventory contents separately.
// In particular, the default command remains run; test is a CLI argument, not a
// different image, entrypoint, daemon or runtime implementation.
func BifroestBuildRequest(platform bib.Platform, binary string) (BuildRequest, error) {
	from, err := platform.SourceOciImage()
	if err != nil {
		return BuildRequest{}, err
	}
	file := sys.BifroestOciBinaryFileLocation(platform.Os)
	directory := sys.BifroestOciBinaryDirLocation(platform.Os)
	if file == "" || directory == "" {
		return BuildRequest{}, fmt.Errorf("cannot resolve Bifröst image binary location for %s", platform.Os)
	}
	return BuildRequest{
		From: from, Os: platform.Os, Arch: platform.Arch,
		BifroestBinarySource: binary,
		PathEnv:              []string{directory}, EntryPoint: []string{file}, Cmd: []string{"run"},
		ExposedPorts:          map[string]struct{}{"22/tcp": {}},
		AddDummyConfiguration: true, AddSkeletonStructure: true,
	}, nil
}
