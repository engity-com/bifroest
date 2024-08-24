//go:build windows

package service

import (
	"syscall"

	"github.com/gliderlabs/ssh"

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
		default:
			return false
		}
	}

	return false
}

func (this *service) onPtyRequest(_ ssh.Context, _ ssh.Pty) bool {
	return false
}
