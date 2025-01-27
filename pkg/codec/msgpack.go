package codec

import (
	"bufio"
	"fmt"
	"io"
	gonet "net"
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
	v.Reset(nil)
}

func NewMsgPackDecoder(r io.Reader) *msgpack.Decoder {
	dec := msgpack.NewDecoder(r)
	return dec
}

func GetPooledMsgPackDecoder(r io.Reader) *msgpack.Decoder {
	bufReader := GetPooledBufReader(r)
	result := decoders.Get().(*msgpack.Decoder)
	result.Reset(bufReader)
	return result
}

func ReleasePooledMsgPackDecoder(v *msgpack.Decoder) {
	decoders.Put(v)
	if vv, ok := v.Buffered().(*bufio.Reader); ok {
		ReleasePooledBufReader(vv)
	}
	v.Reset(nil)
}

func NewMsgPackEncoder(w io.Writer) *msgpack.Encoder {
	enc := msgpack.NewEncoder(w)
	enc.SetOmitEmpty(true)
	enc.SetSortMapKeys(true)
	return enc
}

func GetPooledMsgPackEncoder(w io.Writer) *msgpack.Encoder {
	result := encoders.Get().(*msgpack.Encoder)
	result.Reset(w)
	return result
}

func ReleasePooledMsgPackEncoder(v *msgpack.Encoder) {
	encoders.Put(v)
	v.Reset(nil)
}

func NewMsgPackConn(conn gonet.Conn) MsgPackConn {
	return &msgPackConn{
		conn: conn,
		enc:  NewMsgPackEncoder(conn),
		dec:  NewMsgPackDecoder(conn),
	}
}

// GetPooledMsgPackConn TODO! This should be used instead of [NewMsgPackConn]
// but currently we have concurrency issues here which makes it more unstable rather
// than it helps us to increase the speed.
//
//goland:noinspection GoUnusedExportedFunction
func GetPooledMsgPackConn(conn gonet.Conn) MsgPackConn {
	result := msgPackConns.Get().(*msgPackConn)
	result.conn = conn
	result.enc = GetPooledMsgPackEncoder(conn)
	result.dec = GetPooledMsgPackDecoder(conn)
	result.onClose = func() {
		ReleasePooledMsgPackConn(result)
	}
	return result
}

func ReleasePooledMsgPackConn(v MsgPackConn) {
	instance, ok := v.(*msgPackConn)
	if !ok {
		panic(fmt.Errorf("unsupported connection %T", v))
	}
	if vv := instance.enc; vv != nil {
		ReleasePooledMsgPackEncoder(vv)
	}
	if vv := instance.dec; vv != nil {
		ReleasePooledMsgPackDecoder(vv)
	}
	instance.conn = nil
	instance.enc = nil
	instance.dec = nil
	instance.onClose = nil
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
	gonet.Conn
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
	conn    gonet.Conn
	enc     *msgpack.Encoder
	dec     *msgpack.Decoder
	onClose func()
}

func (this *msgPackConn) Read(b []byte) (int, error) {
	v := this.conn
	if v == nil {
		return -1, io.ErrClosedPipe
	}
	return v.Read(b)
}

func (this *msgPackConn) Write(b []byte) (int, error) {
	v := this.conn
	if v == nil {
		return -1, io.ErrClosedPipe
	}
	return v.Write(b)
}

func (this *msgPackConn) LocalAddr() gonet.Addr {
	v := this.conn
	if v == nil {
		return closedAddr{}
	}
	return v.LocalAddr()
}

func (this *msgPackConn) RemoteAddr() gonet.Addr {
	v := this.conn
	if v == nil {
		return closedAddr{}
	}
	return v.RemoteAddr()
}

func (this *msgPackConn) SetDeadline(t time.Time) error {
	v := this.conn
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.SetDeadline(t)
}

func (this *msgPackConn) SetReadDeadline(t time.Time) error {
	v := this.conn
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.SetReadDeadline(t)
}

func (this *msgPackConn) SetWriteDeadline(t time.Time) error {
	v := this.conn
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.SetWriteDeadline(t)
}

func (this *msgPackConn) Writer() io.Writer {
	v := this.enc
	if v == nil {
		return closedReaderWriter{}
	}
	return v.Writer()
}

func (this *msgPackConn) Encode(vv any) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.Encode(vv)
}

func (this *msgPackConn) EncodeMulti(vv ...any) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeMulti(vv...)
}

func (this *msgPackConn) EncodeValue(vv reflect.Value) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeValue(vv)
}

func (this *msgPackConn) EncodeNil() error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeNil()
}

func (this *msgPackConn) EncodeBool(vv bool) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeBool(vv)
}

func (this *msgPackConn) EncodeDuration(vv time.Duration) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeDuration(vv)
}

func (this *msgPackConn) EncodeMap(vv map[string]any) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeMap(vv)
}

func (this *msgPackConn) EncodeMapSorted(vv map[string]any) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeMapSorted(vv)
}

func (this *msgPackConn) EncodeMapLen(vv int) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeMapLen(vv)
}

func (this *msgPackConn) EncodeUint8(vv uint8) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeUint8(vv)
}

func (this *msgPackConn) EncodeUint16(vv uint16) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeUint16(vv)
}

func (this *msgPackConn) EncodeUint32(vv uint32) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeUint32(vv)
}

func (this *msgPackConn) EncodeUint64(vv uint64) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeUint64(vv)
}

func (this *msgPackConn) EncodeInt8(vv int8) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeInt8(vv)
}

func (this *msgPackConn) EncodeInt16(vv int16) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeInt16(vv)
}

func (this *msgPackConn) EncodeInt32(vv int32) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeInt32(vv)
}

func (this *msgPackConn) EncodeInt64(vv int64) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeInt64(vv)
}

func (this *msgPackConn) EncodeUint(vv uint64) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeUint(vv)
}

func (this *msgPackConn) EncodeInt(vv int64) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeInt(vv)
}

func (this *msgPackConn) EncodeFloat32(vv float32) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeFloat32(vv)
}

func (this *msgPackConn) EncodeFloat64(vv float64) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeFloat64(vv)
}

func (this *msgPackConn) EncodeBytesLen(vv int) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeBytesLen(vv)
}

func (this *msgPackConn) EncodeString(vv string) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeString(vv)
}

func (this *msgPackConn) EncodeBytes(vv []byte) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeBytes(vv)
}

func (this *msgPackConn) EncodeArrayLen(vv int) error {
	v := this.enc
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.EncodeArrayLen(vv)
}

func (this *msgPackConn) Buffered() io.Reader {
	v := this.dec
	if v == nil {
		return closedReaderWriter{}
	}
	return v.Buffered()
}

func (this *msgPackConn) Decode(vv any) error {
	v := this.dec
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.Decode(vv)
}

func (this *msgPackConn) DecodeMulti(vv ...any) error {
	v := this.dec
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.DecodeMulti(vv...)
}

func (this *msgPackConn) DecodeValue(vv reflect.Value) error {
	v := this.dec
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.DecodeValue(vv)
}

func (this *msgPackConn) DecodeNil() error {
	v := this.dec
	if v == nil {
		return io.ErrClosedPipe
	}
	return v.DecodeNil()
}

func (this *msgPackConn) DecodeBool() (bool, error) {
	v := this.dec
	if v == nil {
		return false, io.ErrClosedPipe
	}
	return v.DecodeBool()
}

func (this *msgPackConn) DecodeDuration() (time.Duration, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeDuration()
}

func (this *msgPackConn) DecodeInterface() (any, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.DecodeInterface()
}

func (this *msgPackConn) DecodeInterfaceLoose() (any, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.DecodeInterfaceLoose()
}

func (this *msgPackConn) DecodeRaw() (msgpack.RawMessage, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.DecodeRaw()
}

func (this *msgPackConn) DecodeMapLen() (int, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeMapLen()
}

func (this *msgPackConn) DecodeMap() (map[string]any, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.DecodeMap()
}

func (this *msgPackConn) DecodeUntypedMap() (map[any]any, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.DecodeUntypedMap()
}

func (this *msgPackConn) DecodeTypedMap() (any, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.DecodeTypedMap()
}

func (this *msgPackConn) DecodeFloat32() (float32, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeFloat32()
}

func (this *msgPackConn) DecodeFloat64() (float64, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeFloat64()
}

func (this *msgPackConn) DecodeUint() (uint, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeUint()
}

func (this *msgPackConn) DecodeUint8() (uint8, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeUint8()
}

func (this *msgPackConn) DecodeUint16() (uint16, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeUint16()
}

func (this *msgPackConn) DecodeUint32() (uint32, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeUint32()
}

func (this *msgPackConn) DecodeUint64() (uint64, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeUint64()
}

func (this *msgPackConn) DecodeInt() (int, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeInt()
}

func (this *msgPackConn) DecodeInt8() (int8, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeInt8()
}

func (this *msgPackConn) DecodeInt16() (int16, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeInt16()
}

func (this *msgPackConn) DecodeInt32() (int32, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeInt32()
}

func (this *msgPackConn) DecodeInt64() (int64, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeInt64()
}

func (this *msgPackConn) Query(vv string) ([]any, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.Query(vv)
}

func (this *msgPackConn) DecodeArrayLen() (int, error) {
	v := this.dec
	if v == nil {
		return 0, io.ErrClosedPipe
	}
	return v.DecodeArrayLen()
}

func (this *msgPackConn) DecodeSlice() ([]any, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.DecodeSlice()
}

func (this *msgPackConn) DecodeBytes() ([]byte, error) {
	v := this.dec
	if v == nil {
		return nil, io.ErrClosedPipe
	}
	return v.DecodeBytes()
}

func (this *msgPackConn) DecodeString() (string, error) {
	v := this.dec
	if v == nil {
		return "", io.ErrClosedPipe
	}
	return v.DecodeString()
}

func (this *msgPackConn) NetConn() gonet.Conn {
	if nce, ok := this.conn.(interface{ NetConn() gonet.Conn }); ok {
		return nce.NetConn()
	}
	return nil
}

func (this *msgPackConn) Close() error {
	if vv := this.onClose; vv != nil {
		defer vv()
	}

	if vv := this.conn; vv != nil {
		if err := vv.Close(); err != nil {
			return err
		}
	}
	return nil
}

var (
	bufReaders = sync.Pool{
		New: func() any {
			return bufio.NewReader(nil)
		},
	}
	decoders = sync.Pool{
		New: func() any {
			dec := NewMsgPackDecoder(nil)
			return dec
		},
	}
	encoders = sync.Pool{
		New: func() any {
			return NewMsgPackEncoder(nil)
		},
	}
	msgPackConns = sync.Pool{
		New: func() any {
			return &msgPackConn{}
		},
	}
)

type closedAddr struct{}

func (a closedAddr) Network() string { return "closed" }
func (a closedAddr) String() string  { return a.Network() }

type closedReaderWriter struct{}

func (c closedReaderWriter) Read([]byte) (int, error)  { return 0, io.EOF }
func (c closedReaderWriter) Write([]byte) (int, error) { return 0, io.EOF }
func (c closedReaderWriter) Close() error              { return nil }
