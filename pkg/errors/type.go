package errors

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
)

type Type uint8

const (
	Unknown Type = iota
	System
	Config
	Network
	User
	Permission
	Expired
)

func (t Type) Newf(msg string, args ...any) *Error {
	return Newf(t, msg, args...)
}

func (t Type) IsZero() bool {
	return t == 0
}

func (t Type) IsErr(err error) bool {
	return IsType(err, t)
}

func (t Type) String() string {
	v, ok := typeToStr[t]
	if !ok {
		return "unknown-error-type-" + strconv.FormatUint(uint64(t), 10)
	}
	return v
}

func (t Type) MarshalText() ([]byte, error) {
	v, ok := typeToStr[t]
	if !ok {
		return nil, fmt.Errorf("unknown error type: %d", t)
	}
	return []byte(v), nil
}

func (t *Type) Set(plain string) error {
	candidate, ok := strToType[strings.ToLower(plain)]
	if !ok {
		return fmt.Errorf("unknown error type: %q", plain)
	}
	*t = candidate
	return nil
}

func (t *Type) UnmarshalText(text []byte) error {
	return t.Set(string(text))
}

func (t Type) IsEqualTo(other any) bool {
	switch o := other.(type) {
	case *Type:
		return t == *o
	case Type:
		return t == o
	case string:
		candidate, ok := strToType[strings.ToLower(o)]
		return ok && t == candidate
	case *string:
		candidate, ok := strToType[strings.ToLower(*o)]
		return ok && t == candidate
	default:
		return false
	}
}

func (this Type) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *Type) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this Type) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	return enc.EncodeUint8(uint8(this))
}

func (this *Type) DecodeMsgPack(dec codec.MsgPackDecoder) error {
	v, err := dec.DecodeUint8()
	if err != nil {
		return err
	}
	buf := Type(v)
	_, ok := typeToStr[buf]
	if !ok {
		return fmt.Errorf("unknown error type: %d (msgpck)", v)
	}
	*this = buf
	return nil
}

var (
	strToType = map[string]Type{
		"unknown":    Unknown,
		"system":     System,
		"config":     Config,
		"network":    Network,
		"user":       User,
		"permission": Permission,
		"expired":    Expired,
	}
	typeToStr = func(map[string]Type) map[Type]string {
		result := make(map[Type]string, len(strToType))
		for k, v := range strToType {
			result[v] = k
		}
		return result
	}(strToType)
)
