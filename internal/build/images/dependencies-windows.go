package images

import (
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	Netapi32DllFilename        = `C:\Windows\System32\netapi32.dll`
	ImageContainingNetapi32Dll = "mcr.microsoft.com/windows/servercore:ltsc2022"
)

func (this FetchDependenciesRequest) imageWithNetapi32Dll() string {
	if v := this.ImageWithNetapi32Dll; v != "" {
		return v
	}
	return ImageContainingNetapi32Dll
}

func downloadNetapi32DllFor(ctx context.Context, req FetchDependenciesRequest) (FileDependencies, error) {
	os := req.os()
	arch := req.arch()
	fail := func(err error) (FileDependencies, error) {
		return nil, fmt.Errorf("cannot download netapi32.dll for %v/%v: %w", os, arch, err)
	}

	if os != sys.OsWindows {
		return nil, nil
	}

	targetFn := dependenciesCacheLocationFor(req, "netapi32.dll")

	err := getFileFromImage(ctx, req, req.imageWithNetapi32Dll(), "Files/Windows/System32/netapi32.dll", targetFn)
	if err != nil {
		return fail(err)
	}

	return FileDependencies{{os, arch, targetFn, Netapi32DllFilename, 0644}}, nil
}
