package net

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
)

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
		*this = Host{IP: t.IP}
		return nil
	case *net.IPAddr:
		*this = Host{IP: t.IP}
		return nil
	case *net.TCPAddr:
		*this = Host{IP: t.IP}
		return nil
	case *net.UDPAddr:
		*this = Host{IP: t.IP}
		return nil
	default:
		return errors.New("invalid address type")
	}
}

func (this Host) Clone() Host {
	if v := this.IP; len(v) != 0 {
		return Host{IP: bytes.Clone(v)}
	}

	return Host{Dns: strings.Clone(this.Dns)}
}

func (this Host) StringJoinedWithPort(port uint16) string {
	return net.JoinHostPort(this.String(), strconv.FormatUint(uint64(port), 10))
}
