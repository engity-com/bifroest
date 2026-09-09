//go:build local_build && !local_kind

package alternatives

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func writeToLocalStorage(ctx context.Context, tag name.Tag, img v1.Image) error {
	return writeToLocalDockerDaemon(ctx, tag, img)
}

func ensureInLocalStorage(context.Context, name.Tag, v1.Image) error {
	return nil
}
