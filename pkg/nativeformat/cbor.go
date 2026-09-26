package nativeformat

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var (
	cborEncoder cbor.EncMode
	cborDecoder cbor.DecMode
)

func init() {
	options := cbor.CoreDetEncOptions()
	options.TagsMd = cbor.TagsForbidden
	options.ByteArray = cbor.ByteArrayToByteSlice
	options.BigIntConvert = cbor.BigIntConvertReject
	options.NaNConvert = cbor.NaNConvertReject
	options.InfConvert = cbor.InfConvertReject
	var err error
	cborEncoder, err = options.EncMode()
	if err != nil {
		panic(err)
	}
	cborDecoder, err = (cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		UTF8:              cbor.UTF8RejectInvalid,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
		MaxArrayElements:  4096,
		MaxMapPairs:       128,
		MaxNestedLevels:   16,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

// Marshal encodes a typed wire map and checks that its bytes are acceptable
// to the same strict decoder used for untrusted containers.
func Marshal(value any, maximum int) ([]byte, error) {
	if maximum < 1 {
		return nil, fmt.Errorf("invalid CBOR size limit %d", maximum)
	}
	if validator, ok := value.(interface{ ValidateNativeWire() error }); ok {
		if err := validator.ValidateNativeWire(); err != nil {
			return nil, err
		}
	}
	encoded, err := cborEncoder.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("cannot encode native CBOR payload: %w", err)
	}
	if len(encoded) > maximum || len(encoded) == 0 || encoded[0]>>5 != 5 {
		return nil, fmt.Errorf("native CBOR payload must be a map of at most %d bytes", maximum)
	}
	var inspected any
	if err := cborDecoder.Unmarshal(encoded, &inspected); err != nil {
		return nil, fmt.Errorf("cannot validate native CBOR payload: %w", err)
	}
	if err := validateCBORValue(inspected); err != nil {
		return nil, err
	}
	canonical, err := cborEncoder.Marshal(inspected)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return nil, fmt.Errorf("native CBOR payload is not canonically encoded")
	}
	return encoded, nil
}

// Unmarshal requires a fresh, typed wire schema; re-encoding rejects alternate
// but semantically equivalent encodings before they can enter a signed chain.
func Unmarshal[T any](encoded []byte, maximum int) (T, error) {
	var zero T
	var result T
	if maximum < 1 || len(encoded) == 0 || len(encoded) > maximum || encoded[0]>>5 != 5 {
		return zero, fmt.Errorf("native CBOR payload must be a map of at most %d bytes", maximum)
	}
	var inspected any
	if err := cborDecoder.Unmarshal(encoded, &inspected); err != nil {
		return zero, fmt.Errorf("cannot inspect native CBOR payload: %w", err)
	}
	if err := validateCBORValue(inspected); err != nil {
		return zero, err
	}
	if err := cborDecoder.Unmarshal(encoded, &result); err != nil {
		return zero, fmt.Errorf("cannot decode native CBOR payload: %w", err)
	}
	canonical, err := cborEncoder.Marshal(result)
	if err != nil {
		return zero, fmt.Errorf("cannot re-encode native CBOR payload: %w", err)
	}
	if !bytes.Equal(encoded, canonical) {
		return zero, fmt.Errorf("native CBOR payload is not canonically encoded")
	}
	if validator, ok := any(result).(interface{ ValidateNativeWire() error }); ok {
		if err := validator.ValidateNativeWire(); err != nil {
			return zero, err
		}
	}
	return result, nil
}

func validateCBORValue(value any) error {
	switch v := value.(type) {
	case uint64, int64, string, []byte, bool:
		return nil
	case []any:
		for _, entry := range v {
			if err := validateCBORValue(entry); err != nil {
				return err
			}
		}
	case map[any]any:
		for key, entry := range v {
			if _, ok := key.(uint64); !ok {
				return fmt.Errorf("native CBOR map has a non-unsigned-integer key")
			}
			if err := validateCBORValue(entry); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("native CBOR contains unsupported value type %T", value)
	}
	return nil
}
