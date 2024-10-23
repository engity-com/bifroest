package sys

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
)

var (
	ErrUnknownSignal = errors.New("unknown signal")
)

type Signal uint16

func (this Signal) SendToProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return this.sendToProcess(p)
}

func (this Signal) String() string {
	if this == 0 {
		return ""
	}

	str, ok := signalToStr[this]
	if !ok {
		return prefix0x + strconv.FormatUint(uint64(this), 16)
	}
	return prefixSig + str
}

func (this *Signal) Set(plain string) error {
	if len(plain) == 0 {
		*this = 0
		return nil
	}

	plainU := strings.ToUpper(plain)
	if strings.HasPrefix(plainU, prefixSig) {
		lookup := plainU[prefixSigLen:]
		candidate, ok := strToSignal[lookup]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownSignal, plain)
		}
		*this = candidate
		return nil
	}

	if strings.HasPrefix(plainU, prefix0X) {
		lookup := plainU[prefix0XLen:]
		candidate, err := strconv.ParseUint(lookup, 16, 8)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrUnknownSignal, plain)
		}
		*this = Signal(candidate)
		return nil
	}

	if candidate, ok := strToSignal[plainU]; ok {
		*this = candidate
		return nil
	}

	if candidate, err := strconv.ParseUint(plainU, 10, 8); err == nil {
		*this = Signal(candidate)
		return nil
	}

	return fmt.Errorf("%w: %s", ErrUnknownSignal, plain)
}

func (this Signal) MarshalText() ([]byte, error) {
	return []byte(this.String()), nil
}

func (this *Signal) UnmarshalText(text []byte) error {
	return this.Set(string(text))
}

func (this Signal) IsZero() bool {
	return this == 0
}

func (this Signal) Native() syscall.Signal {
	return syscall.Signal(this)
}

func (this Signal) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case Signal:
		return this == v
	case *Signal:
		return this == *v
	case syscall.Signal:
		return this.Native() == v
	case *syscall.Signal:
		return this.Native() == *v
	default:
		return false
	}
}

func (this Signal) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *Signal) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this Signal) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	return enc.EncodeUint16(uint16(this))
}

func (this *Signal) DecodeMsgPack(dec codec.MsgPackDecoder) error {
	v, err := dec.DecodeUint16()
	if err != nil {
		return err
	}
	*this = Signal(v)
	return nil
}

const (
	prefixSig    = "SIG"
	prefixSigLen = len(prefixSig)

	prefix0x    = "0x"
	prefix0X    = "0X"
	prefix0XLen = len(prefix0X)
)

var (
	signalToStr = func(in map[string]Signal) map[Signal]string {
		result := make(map[Signal]string, len(in))
		for str, sig := range in {
			result[sig] = str
		}
		return result
	}(strToSignal)
)
