package net

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

func NewHostPort(in string) (result HostPort, err error) {
	err = result.Set(in)
	return
}

func MustNewHostPort(in string) HostPort {
	result, err := NewHostPort(in)
	common.Must(err)
	return result
}

type HostPort struct {
	Host Host
	Port uint16
}

func (this HostPort) String() string {
	host := this.Host.String()
	if host == "" && this.Port == 0 {
		return ""
	}

	if strings.IndexByte(host, ':') >= 0 {
		host = "[" + host + "]"
	}

	return host + ":" + strconv.FormatUint(uint64(this.Port), 10)
}

func (this HostPort) MarshalText() ([]byte, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}

	host, err := this.Host.MarshalText()
	if err != nil {
		return nil, err
	}
	if len(host) == 0 && this.Port == 0 {
		return []byte{}, nil
	}
	port := []byte(strconv.FormatUint(uint64(this.Port), 10))

	if bytes.IndexByte(host, ':') >= 0 {
		host = bytes.Join([][]byte{{'['}, host, {']'}}, nil)
	}
	return bytes.Join([][]byte{host, port}, []byte{':'}), nil
}

func (this *HostPort) UnmarshalText(in []byte) error {
	if len(in) == 0 {
		*this = HostPort{}
		return nil
	}

	var buf HostPort

	var hostPart, portPart []byte
	if in[0] == '[' {
		n := bytes.IndexByte(in, ']')
		if n == -1 || len(in) < n+2 || in[n+1] != ':' {
			return errors.Config.Newf("illegal host-port: %s", string(in))
		}
		hostPart = in[1:n]
		portPart = in[n+2:]
	} else {
		n := bytes.IndexByte(in, ':')
		if n == -1 || len(in) < n+1 {
			return errors.Config.Newf("illegal host-port: %s", string(in))
		}
		hostPart = in[:n]
		portPart = in[n+1:]
	}
	if bytes.IndexByte(portPart, ':') >= 0 {
		return errors.Config.Newf("illegal host-port: %s", string(in))
	}

	if err := buf.Host.UnmarshalText(hostPart); err != nil {
		return errors.Config.Newf("illegal host-port: %w", err)
	}
	port, err := strconv.ParseUint(string(portPart), 10, 16)
	if err != nil {
		return errors.System.Newf("illegal host-port: invalid port %s", string(portPart))
	}
	if port == 0 {
		return errors.System.Newf("illegal host-port: invalid port %d", port)
	}
	buf.Port = uint16(port)

	*this = buf
	return nil
}

func (this *HostPort) Set(in string) error {
	return this.UnmarshalText([]byte(in))
}

func (this HostPort) Clone() HostPort {
	return HostPort{
		this.Host.Clone(),
		this.Port,
	}
}

func (this HostPort) IsZero() bool {
	return this.Host.IsZero() &&
		this.Port == 0
}

func (this HostPort) Validate() error {
	if err := this.Host.Validate(); err != nil {
		return errors.Config.Newf("illegal host-port: %w", err)
	}
	if (!this.Host.IsZero() && this.Port == 0) || (this.Host.IsZero() && this.Port > 0) {
		return errors.Config.Newf("illegal host-port: %v", this)
	}
	return nil
}

func (this HostPort) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case HostPort:
		return this.isEqualTo(&v)
	case *HostPort:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this HostPort) isEqualTo(other *HostPort) bool {
	return this.Host.IsEqualTo(other.Host) &&
		this.Port == other.Port
}
