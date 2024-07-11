package common

import (
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
)

func NewNetAddress(plain string) (NetAddress, error) {
	var buf NetAddress
	if err := buf.Set(plain); err != nil {
		return NetAddress{}, nil
	}
	return buf, nil
}

func MustNewNetAddress(plain string) NetAddress {
	buf, err := NewNetAddress(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type NetAddress struct {
	v net.Addr
}

func (this NetAddress) IsZero() bool {
	return this.v == nil
}

func (this NetAddress) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this NetAddress) String() string {
	pv := this.v
	if pv == nil {
		return ""
	}

	switch v := pv.(type) {
	case *net.TCPAddr:
		return v.String()
	default:
		panic(fmt.Errorf("illegal address type: %v(%v)", reflect.TypeOf(pv), pv))
	}
}

func (this NetAddress) Listen() (net.Listener, error) {
	pv := this.v
	if pv == nil {
		return nil, fmt.Errorf("cannot listen to empty address")
	}

	switch v := pv.(type) {
	case *net.TCPAddr:
		return net.ListenTCP(v.Network(), v)
	default:
		panic(fmt.Errorf("illegal address type: %v(%v)", reflect.TypeOf(pv), pv))
	}
}

func (this *NetAddress) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		this.v = nil
		return nil
	}

	network := "tcp"
	address := string(text)
	pps := strings.SplitN(address, ":", 2)
	if len(pps) > 1 {
		switch pps[0] {
		case "tcp", "tcp4", "tcp6":
			network = pps[0]
			address = pps[1]
		}
	}

	var resolver func() (net.Addr, error)
	switch network {
	case "tcp", "tcp4", "tcp6":
		resolver = func() (net.Addr, error) { return net.ResolveTCPAddr(network, address) }
	default:
		panic(fmt.Errorf("illegal network %q for requested address %q", network, string(text)))
	}

	v, err := resolver()
	if err != nil {
		return fmt.Errorf("illegal network address %q: %w", string(text), err)
	}

	this.v = v
	return nil
}

func (this *NetAddress) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this NetAddress) Get() net.Addr {
	return this.v
}

func (this NetAddress) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case NetAddress:
		return this.isEqualTo(&v)
	case *NetAddress:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this NetAddress) isEqualTo(other *NetAddress) bool {
	return reflect.DeepEqual(this.v, other.v)
}

type NetAddresses []NetAddress

func (this *NetAddresses) Trim() error {
	if this == nil {
		return nil
	}
	*this = slices.DeleteFunc(*this, func(e NetAddress) bool {
		return e.IsZero()
	})
	return nil
}

func (this *NetAddresses) Validate() error {
	return nil
}

func (this NetAddresses) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case NetAddresses:
		return this.isEqualTo(&v)
	case *NetAddresses:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this NetAddresses) isEqualTo(other *NetAddresses) bool {
	if len(this) != len(*other) {
		return false
	}
	for i, tv := range this {
		if !tv.IsEqualTo(&(*other)[i]) {
			return false
		}
	}
	return true
}
