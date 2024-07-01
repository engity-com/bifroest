package common

import "github.com/engity-com/bifroest/pkg/net"

type Remote interface {
	User() string
	Host() net.Host
	String() string
}
