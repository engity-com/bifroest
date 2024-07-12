package common

import "net"

type Remote interface {
	User() string
	Addr() net.Addr
}
