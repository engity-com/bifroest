//go:build linux

package service

import (
	"syscall"

	"github.com/engity-com/bifroest/pkg/errors"
)

func (this *service) isAcceptableNewConnectionError(err error) bool {
	if err == nil {
		return false
	}

	var sce syscall.Errno
	if errors.As(err, &sce) {
		switch sce {
		case syscall.ECONNREFUSED, syscall.ETIMEDOUT, syscall.EHOSTDOWN, syscall.ENETUNREACH:
			return true
		}
	}

	return false
}
