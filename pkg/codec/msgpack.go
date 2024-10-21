package codec

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

func GetPooledBufReader(r io.Reader) *bufio.Reader {
	result := bufReaders.Get().(*bufio.Reader)
	result.Reset(r)
	return result
}

func ReleasePooledBufReader(v *bufio.Reader) {
	bufReaders.Put(v)
}

func GetPooledMsgPackDecoder(r io.Reader) *msgpack.Decoder {
	bufReader := GetPooledBufReader(r)
	result := decoders.Get().(*msgpack.Decoder)
	result.Reset(bufReader)
	return result
}

func ReleasePooledMsgPackDecoder(v *msgpack.Decoder) {
	decoders.Put(v)
	ReleasePooledBufReader(v.Buffered().(*bufio.Reader))
}

func GetPooledMsgPackEncoder(w io.Writer) *msgpack.Encoder {
	result := encoders.Get().(*msgpack.Encoder)
	result.Reset(w)
	return result
}

func ReleasePooledMsgPackEncoder(v *msgpack.Encoder) {
	encoders.Put(v)
}

func GetPooledMsgPackConn(conn net.Conn) MsgPackConn {
	result := msgPackConns.Get().(*msgPackConn)
	result.Conn = conn
	result.Encoder = GetPooledMsgPackEncoder(conn)
	result.Decoder = GetPooledMsgPackDecoder(conn)
	return result
}

func ReleasePooledMsgPackConn(v MsgPackConn) {
	instance, ok := v.(*msgPackConn)
	if !ok {
		panic(fmt.Errorf("unsupported connection %T", v))
	}
	ReleasePooledMsgPackEncoder(instance.Encoder)
	ReleasePooledMsgPackDecoder(instance.Decoder)
	msgPackConns.Put(instance)
}

type MsgPackEncoder interface {
	Writer() io.Writer
	Encode(v any) error
	EncodeMulti(v ...any) error
	EncodeValue(v reflect.Value) error
	EncodeNil() error
	EncodeBool(value bool) error
	EncodeDuration(d time.Duration) error
	EncodeMap(m map[string]any) error
	EncodeMapSorted(m map[string]any) error
	EncodeMapLen(l int) error
	EncodeUint8(n uint8) error
	EncodeUint16(n uint16) error
	EncodeUint32(n uint32) error
	EncodeUint64(n uint64) error
	EncodeInt8(n int8) error
	EncodeInt16(n int16) error
	EncodeInt32(n int32) error
	EncodeInt64(n int64) error
	EncodeUint(n uint64) error
	EncodeInt(n int64) error
	EncodeFloat32(n float32) error
	EncodeFloat64(n float64) error
	EncodeBytesLen(l int) error
	EncodeString(v string) error
	EncodeBytes(v []byte) error
	EncodeArrayLen(l int) error
}

type MsgPackDecoder interface {
	Buffered() io.Reader
	Decode(v any) error
	DecodeMulti(v ...any) error
	DecodeValue(v reflect.Value) error
	DecodeNil() error
	DecodeBool() (bool, error)
	DecodeDuration() (time.Duration, error)
	DecodeInterface() (any, error)
	DecodeInterfaceLoose() (any, error)
	DecodeRaw() (msgpack.RawMessage, error)
	DecodeMapLen() (int, error)
	DecodeMap() (map[string]any, error)
	DecodeUntypedMap() (map[any]any, error)
	DecodeTypedMap() (any, error)
	DecodeFloat32() (float32, error)
	DecodeFloat64() (float64, error)
	DecodeUint() (uint, error)
	DecodeUint8() (uint8, error)
	DecodeUint16() (uint16, error)
	DecodeUint32() (uint32, error)
	DecodeUint64() (uint64, error)
	DecodeInt() (int, error)
	DecodeInt8() (int8, error)
	DecodeInt16() (int16, error)
	DecodeInt32() (int32, error)
	DecodeInt64() (int64, error)
	Query(query string) ([]any, error)
	DecodeArrayLen() (int, error)
	DecodeSlice() ([]any, error)
	DecodeBytes() ([]byte, error)
	DecodeString() (string, error)
}

type MsgPackConn interface {
	net.Conn
	MsgPackEncoder
	MsgPackDecoder
}

type MsgPackCustomDecoder interface {
	DecodeMsgPack(dec MsgPackDecoder) error
}

type MsgPackCustomEncoder interface {
	EncodeMsgPack(enc MsgPackEncoder) error
}

type msgPackConn struct {
	net.Conn
	*msgpack.Encoder
	*msgpack.Decoder
}

func (this *msgPackConn) NetConn() net.Conn {
	if nce, ok := this.Conn.(interface{ NetConn() net.Conn }); ok {
		return nce.NetConn()
	}
	return nil
}

func (this *msgPackConn) Close() error {
	defer ReleasePooledMsgPackConn(this)
	return this.Conn.Close()
}

var (
	bufReaders = sync.Pool{
		New: func() any {
			return bufio.NewReader(nil)
		},
	}
	decoders = sync.Pool{
		New: func() any {
			dec := msgpack.NewDecoder(nil)
			return dec
		},
	}
	encoders = sync.Pool{
		New: func() any {
			enc := msgpack.NewEncoder(nil)
			enc.SetOmitEmpty(true)
			enc.SetSortMapKeys(true)
			return enc
		},
	}
	msgPackConns = sync.Pool{
		New: func() any {
			return &msgPackConn{}
		},
	}
)
