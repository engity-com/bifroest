//go:build windows

package environment

import (
	"runtime"
	"slices"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/kardianos/osext"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	BifroestBinaryMountTarget = `C:\Program Files\Engity\Bifroest\bifroest.exe`
)

func (this *DockerRepository) enrichContainerConfigOsSpecific(_ Request, hostOs, hostArch string, target *container.Config) (err error) {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Config.Newf(msg, args...))
	}

	if len(this.conf.BlockCommand) == 0 {
		switch hostOs {
		case "windows":
			if hostArch == runtime.GOARCH {
				target.Cmd = []string{BifroestBinaryMountTarget, `forever`}
			} else {
				target.Cmd = slices.Clone(WindowsRunForeverCommand)
			}
		case "linux":
			target.Cmd = slices.Clone(LinuxRunForeverCommand)
		default:
			return failf("blockCommand required but not configured for docker environment where host os is neither windows nor linux")
		}
	}

	return nil
}

func (this *DockerRepository) enrichHostConfigOsSpecific(_ Request, hostOs, hostArch string, target *container.HostConfig) error {
	fail := func(err error) error {
		return err
	}

	switch hostOs {
	case "windows":
		if hostArch == runtime.GOARCH {
			efn, err := osext.Executable()
			if err != nil {
				return fail(errors.System.Newf("cannot resolve the location of the server's executable location: %w", err))
			}
			target.Mounts = append(target.Mounts, mount.Mount{
				Type:     mount.TypeBind,
				Source:   efn,
				Target:   BifroestBinaryMountTarget,
				ReadOnly: true,
				BindOptions: &mount.BindOptions{
					NonRecursive:     true,
					CreateMountpoint: true,
				},
			})
		}
	}

	return nil
}
