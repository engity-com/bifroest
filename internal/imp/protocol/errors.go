package protocol

import (
	gonet "net"
	"reflect"
	"syscall"

	"github.com/engity-com/bifroest/pkg/errors"
)

func reWrapIfUserFacingErrors(in error, targets ...error) error {
	for _, target := range targets {
		val := reflect.ValueOf(target)
		ptr := reflect.New(val.Type())
		ptr.Elem().Set(val)
		pTarget := ptr.Interface()

		if errors.As(in, pTarget) {
			tErr := (ptr.Elem().Interface()).(error)
			return &errors.Error{
				Message:    tErr.Error(),
				Cause:      tErr,
				Type:       errors.Network,
				UserFacing: true,
			}
		}
	}
	return in
}

func reWrapIfUserFacingNetworkErrors(in error) error {
	return reWrapIfUserFacingErrors(in,
		(*gonet.DNSError)(nil),
		(*gonet.AddrError)(nil),
		(gonet.InvalidAddrError)(""),
		(gonet.UnknownNetworkError)(""),
		(*gonet.ParseError)(nil),
		(syscall.Errno)(0),
		(*gonet.OpError)(nil),
	)
}
