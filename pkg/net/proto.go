package net

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/errors"
)

type Proto uint8

const (
	ProtoTcp Proto = iota
)

func (this Proto) String() string {
	v, ok := protoToName[this]
	if !ok {
		return fmt.Sprintf("illegal-proto-%d", this)
	}
	return v
}

func (this Proto) MarshalText() ([]byte, error) {
	v, ok := protoToName[this]
	if !ok {
		return nil, errors.Config.Newf("illegal proto: %d", this)
	}
	return []byte(v), nil
}

func (this *Proto) UnmarshalText(in []byte) error {
	v, ok := nameToProto[string(in)]
	if !ok {
		return errors.Config.Newf("illegal proto: %s", string(in))
	}
	*this = v
	return nil
}

func (this *Proto) Set(in string) error {
	return this.UnmarshalText([]byte(in))
}

func (this Proto) Clone() Proto {
	return this
}

func (this Proto) IsZero() bool {
	return false
}

func (this Proto) Validate() error {
	_, ok := protoToName[this]
	if !ok {
		return errors.Config.Newf("illegal proto: %d", this)
	}
	return nil
}

func (this Proto) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Proto:
		return this.isEqualTo(&v)
	case *Proto:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Proto) isEqualTo(other *Proto) bool {
	return this == *other
}

var (
	protoToName = map[Proto]string{
		ProtoTcp: "tcp",
	}
	nameToProto = func(in map[Proto]string) map[string]Proto {
		result := make(map[string]Proto, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(protoToName)
)
