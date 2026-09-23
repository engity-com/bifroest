package nativeformat

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Timestamp uses the same two-element CBOR array in every native wire schema.
// Encoding time.Time directly would otherwise depend on library time options.
type Timestamp struct {
	Seconds     int64
	Nanoseconds uint32
}

func (this Timestamp) MarshalCBOR() ([]byte, error) {
	if this.Nanoseconds >= 1e9 {
		return nil, fmt.Errorf("invalid native timestamp nanoseconds %d", this.Nanoseconds)
	}
	return cborEncoder.Marshal([2]any{this.Seconds, this.Nanoseconds})
}

func (this *Timestamp) UnmarshalCBOR(encoded []byte) error {
	var fields []cbor.RawMessage
	if err := cborDecoder.Unmarshal(encoded, &fields); err != nil {
		return err
	}
	if len(fields) != 2 {
		return fmt.Errorf("native timestamp must have two elements")
	}
	var result Timestamp
	if err := cborDecoder.Unmarshal(fields[0], &result.Seconds); err != nil {
		return err
	}
	if err := cborDecoder.Unmarshal(fields[1], &result.Nanoseconds); err != nil {
		return err
	}
	if result.Nanoseconds >= 1e9 {
		return fmt.Errorf("invalid native timestamp nanoseconds %d", result.Nanoseconds)
	}
	*this = result
	return nil
}

func TimestampOf(value time.Time) Timestamp {
	return Timestamp{Seconds: value.Unix(), Nanoseconds: uint32(value.Nanosecond())}
}

func (this Timestamp) Time() (time.Time, error) {
	if this.Nanoseconds >= 1e9 {
		return time.Time{}, fmt.Errorf("invalid native timestamp nanoseconds %d", this.Nanoseconds)
	}
	return time.Unix(this.Seconds, int64(this.Nanoseconds)).UTC(), nil
}
