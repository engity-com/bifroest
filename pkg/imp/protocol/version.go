package protocol

import "github.com/vmihailenco/msgpack/v5"

const CurrentVersion = Version(1)

type Version uint16

func (this Version) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeUint16(uint16(this)); err != nil {
		return err
	}
	return nil
}

func (this *Version) DecodeMsgpack(dec *msgpack.Decoder) error {
	if v, err := dec.DecodeUint16(); err != nil {
		return err
	} else {
		*this = Version(v)
	}
	return nil
}
