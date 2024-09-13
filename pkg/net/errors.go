package net

import (
	"io"

	"github.com/engity-com/bifroest/pkg/errors"
)

func IsClosedError(err error) bool {
	return err != nil && (errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF))
}
