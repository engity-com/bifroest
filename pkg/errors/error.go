package errors

import (
	"errors"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
)

func Newf(t Type, msg string, args ...any) *Error {
	buf := fmt.Errorf(msg, args...)
	err := errors.Unwrap(buf)
	var ee *Error
	if errors.As(err, &ee) {
		t = ee.Type
	}
	return &Error{
		Message: buf.Error(),
		Cause:   err,
		Type:    t,
	}
}

func IsType(err error, t Type, otherT ...Type) bool {
	var ee *Error
	if errors.As(err, &ee) {
		if ee.Type == t {
			return true
		}
		for _, ot := range otherT {
			if ee.Type == ot {
				return true
			}
		}
		return IsType(ee.Cause, t, otherT...)
	}
	return false
}

type Error struct {
	Message    string
	Cause      error
	Type       Type
	UserFacing bool
}

func (this *Error) Error() string {
	return this.Message
}

func (this *Error) Unwrap() error {
	return this.Cause
}

func (this *Error) Extendf(msg string, args ...any) *Error {
	return &Error{
		Message: fmt.Sprintf("%v: "+msg, append([]any{this}, args...)...),
		Cause:   this,
		Type:    this.Type,
	}
}

func (this *Error) Extend(args ...any) *Error {
	if len(args) == 0 {
		return this
	}
	return &Error{
		Message: fmt.Sprintf("%v: %v", this, fmt.Sprint(args...)),
		Cause:   this,
		Type:    this.Type,
	}
}

func IsError(err error) (eErr *Error, ok bool) {
	ok = As(err, &eErr)
	return
}

func EncodeMsgPack(err error, using codec.MsgPackEncoder) error {
	if err == nil {
		return Error{}.EncodeMsgPack(using)
	}

	eErr, ok := IsError(err)
	if !ok {
		eErr = &Error{
			Type:    System,
			Message: err.Error(),
		}
	}
	return eErr.EncodeMsgPack(using)
}

func DecodeMsgPack(using codec.MsgPackDecoder) (error, error) {
	var buf Error
	if err := buf.DecodeMsgPack(using); err != nil {
		return nil, err
	}
	if buf.Type == 0 {
		return nil, nil
	}
	return &buf, nil
}

func (this Error) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *Error) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this Error) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := this.Type.EncodeMsgPack(enc); err != nil {
		return err
	}
	if this.Type != 0 {
		if err := enc.EncodeString(this.Message); err != nil {
			return err
		}
		if err := enc.EncodeBool(this.UserFacing); err != nil {
			return err
		}
	}
	return nil
}

func (this *Error) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	var buf Error
	if err = buf.Type.DecodeMsgPack(dec); err != nil {
		return err
	}
	if buf.Type != 0 {
		if buf.Message, err = dec.DecodeString(); err != nil {
			return err
		}
		if buf.UserFacing, err = dec.DecodeBool(); err != nil {
			return err
		}
	}
	*this = buf
	return nil
}
