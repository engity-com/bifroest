package net

import (
	"bytes"
	"net"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

func NewHost(in string) (result Host, err error) {
	err = result.Set(in)
	return
}

func MustNewHost(in string) Host {
	result, err := NewHost(in)
	common.Must(err)
	return result
}

type Host struct {
	IP  net.IP
	Dns string
}

func (this Host) String() string {
	if v := this.IP; len(v) != 0 {
		return v.String()
	}
	return strings.Clone(this.Dns)
}

func (this Host) MarshalText() ([]byte, error) {
	if v := this.IP; len(v) != 0 {
		return v.MarshalText()
	}
	return []byte(this.Dns), nil
}

func (this *Host) UnmarshalText(in []byte) error {
	if len(in) == 0 {
		*this = Host{}
		return nil
	}

	if v := net.ParseIP(string(in)); v != nil {
		*this = Host{IP: v}
		return nil
	}

	*this = Host{Dns: string(in)}
	return nil
}

func (this *Host) Set(in string) error {
	return this.UnmarshalText([]byte(in))
}

func (this *Host) SetNetAddr(in net.Addr) error {
	switch t := in.(type) {
	case *net.IPNet:
		if len(t.IP) == 0 {
			return errors.Config.Newf("invalid address with empty IP")
		}
		*this = Host{IP: t.IP}
		return nil
	case *net.IPAddr:
		if len(t.IP) == 0 {
			return errors.Config.Newf("invalid address with empty IP")
		}
		*this = Host{IP: t.IP}
		return nil
	case *net.TCPAddr:
		if len(t.IP) == 0 {
			return errors.Config.Newf("invalid address with empty IP")
		}
		*this = Host{IP: t.IP}
		return nil
	case *net.UDPAddr:
		if len(t.IP) == 0 {
			return errors.Config.Newf("invalid address with empty IP")
		}
		*this = Host{IP: t.IP}
		return nil
	default:
		return errors.Config.Newf("invalid address type: %v", in)
	}
}

func (this Host) Clone() Host {
	if v := this.IP; len(v) != 0 {
		return Host{IP: bytes.Clone(v)}
	}

	return Host{Dns: strings.Clone(this.Dns)}
}

func (this Host) WithPort(port uint16) (HostPort, error) {
	result := HostPort{this, port}
	if err := result.Validate(); err != nil {
		return HostPort{}, err
	}
	return result, nil
}

func (this Host) IsZero() bool {
	return len(this.IP) == 0 && this.Dns == ""
}

func (this Host) Validate() error {
	switch len(this.IP) {
	case net.IPv4len, net.IPv6len, 0:
		return nil
	default:
		return errors.Config.Newf("illegal IP address: %v", this.IP)
	}
}

func (this Host) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Host:
		return this.isEqualTo(&v)
	case *Host:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Host) isEqualTo(other *Host) bool {
	return bytes.Equal(this.IP, other.IP) &&
		this.Dns == other.Dns
}
