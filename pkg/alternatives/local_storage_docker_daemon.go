//go:build local_build

package alternatives

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"

	"github.com/engity-com/bifroest/pkg/errors"
)

func writeToLocalDockerDaemon(ctx context.Context, tag name.Tag, img v1.Image) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot write oci image %v to local daemon: %w", tag, err)
	}

	if _, err := daemon.Write(tag, img, daemon.WithContext(ctx)); err != nil {
		return fail(err)
	}

	return nil
}
