package wire

import (
	"fmt"
	"io"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

const MaxWireResultBytes = 16 << 20

type wireResult struct {
	Version uint8           `cbor:"1,keyasint"`
	Payload cbor.RawMessage `cbor:"2,keyasint"`
}

func EncodeWireResult(value any) ([]byte, error) {
	payload, err := cbor.Marshal(value)
	if err != nil {
		return nil, err
	}
	encoded, err := cbor.Marshal(wireResult{Version: 1, Payload: payload})
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxWireResultBytes {
		return nil, fmt.Errorf("management response exceeds %d bytes", MaxWireResultBytes)
	}
	return encoded, nil
}

func DecodeWireResult(input io.Reader, target any) error {
	data, err := io.ReadAll(io.LimitReader(input, MaxWireResultBytes+1))
	if err != nil {
		return err
	}
	if len(data) > MaxWireResultBytes {
		return fmt.Errorf("management response exceeds %d bytes", MaxWireResultBytes)
	}
	var frame wireResult
	if err := cbor.Unmarshal(data, &frame); err != nil {
		return err
	}
	if frame.Version != 1 || len(frame.Payload) == 0 {
		return fmt.Errorf("unsupported or empty management response")
	}
	mode, err := (cbor.DecOptions{
		DefaultMapType: reflect.TypeFor[map[string]any](),
		DupMapKey:      cbor.DupMapKeyEnforcedAPF,
	}).DecMode()
	if err != nil {
		return err
	}
	return mode.Unmarshal(frame.Payload, target)
}
