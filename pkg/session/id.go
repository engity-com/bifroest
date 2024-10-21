package session

import (
	"bytes"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/common"
)

func NewId() (Id, error) {
	raw, err := uuid.NewRandom()
	if err != nil {
		return Id{}, err
	}
	return Id(raw), nil
}

func MustNewId() Id {
	id, err := NewId()
	common.Must(err)
	return id
}

type Id uuid.UUID

func (this Id) String() string {
	return uuid.UUID(this).String()
}

func (this Id) IsZero() bool {
	for _, v := range this {
		if v != 0 {
			return false
		}
	}
	return true
}

func (this Id) MarshalText() (text []byte, err error) {
	return uuid.UUID(this).MarshalText()
}

func (this *Id) UnmarshalText(text []byte) error {
	var buf uuid.UUID
	if err := buf.UnmarshalText(text); err != nil {
		return err
	}
	*this = Id(buf)
	return nil
}

func (this Id) MarshalBinary() (b []byte, err error) {
	if this.IsZero() {
		return nil, nil
	}
	return uuid.UUID(this).MarshalBinary()
}

func (this *Id) UnmarshalBinary(b []byte) error {
	if len(b) == 0 {
		*this = Id{}
		return nil
	}

	var buf uuid.UUID
	if err := buf.UnmarshalBinary(b); err != nil {
		return err
	}
	*this = Id(buf)
	return nil
}

func (this Id) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *Id) DecodeMsgpack(dec *msgpack.Decoder) error {
	return this.DecodeMsgPack(dec)
}

func (this Id) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	b, err := this.MarshalBinary()
	if err != nil {
		return err
	}
	return enc.EncodeBytes(b)
}

func (this *Id) DecodeMsgPack(dec codec.MsgPackDecoder) error {
	b, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	return this.UnmarshalBinary(b)
}

func (this *Id) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this Id) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Id:
		return bytes.Equal(this[:], v[:])
	case *Id:
		return bytes.Equal(this[:], (*v)[:])
	case uuid.UUID:
		return bytes.Equal(this[:], v[:])
	case *uuid.UUID:
		return bytes.Equal(this[:], (*v)[:])
	default:
		return false
	}
}
