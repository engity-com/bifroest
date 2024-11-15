package net

import (
	"fmt"
	gonet "net"
	"reflect"
	"slices"
	"strings"
)

func NewAddress(plain string) (Address, error) {
	var buf Address
	if err := buf.Set(plain); err != nil {
		return Address{}, nil
	}
	return buf, nil
}

func MustNewAddress(plain string) Address {
	buf, err := NewAddress(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Address struct {
	v gonet.Addr
}

func (this Address) IsZero() bool {
	return this.v == nil
}

func (this Address) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this Address) String() string {
	pv := this.v
	if pv == nil {
		return ""
	}

	switch v := pv.(type) {
	case *gonet.TCPAddr:
		return v.String()
	default:
		panic(fmt.Errorf("illegal address type: %v(%v)", reflect.TypeOf(pv), pv))
	}
}

func (this Address) Listen() (gonet.Listener, error) {
	pv := this.v
	if pv == nil {
		return nil, fmt.Errorf("cannot listen to empty address")
	}

	switch v := pv.(type) {
	case *gonet.TCPAddr:
		return gonet.ListenTCP(v.Network(), v)
	default:
		panic(fmt.Errorf("illegal address type: %v(%v)", reflect.TypeOf(pv), pv))
	}
}

func (this *Address) UnmarshalText(text []byte) error {
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

	var resolver func() (gonet.Addr, error)
	switch network {
	case "tcp", "tcp4", "tcp6":
		resolver = func() (gonet.Addr, error) { return gonet.ResolveTCPAddr(network, address) }
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

func (this *Address) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Address) Get() gonet.Addr {
	return this.v
}

func (this Address) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Address:
		return this.isEqualTo(&v)
	case *Address:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Address) isEqualTo(other *Address) bool {
	return reflect.DeepEqual(this.v, other.v)
}

type NetAddresses []Address

func (this *NetAddresses) Trim() error {
	if this == nil {
		return nil
	}
	*this = slices.DeleteFunc(*this, func(e Address) bool {
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
