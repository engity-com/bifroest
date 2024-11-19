package images

import (
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/engity-com/bifroest/pkg/common"
)

type Image interface {
	v1.Image
	io.Closer
}

type image struct {
	v1.Image

	closers []io.Closer
}

func (this *image) Close() (rErr error) {
	for _, closer := range this.closers {
		//goland:noinspection GoDeferInLoop
		defer common.KeepCloseError(&rErr, closer)
	}
	return nil
}
