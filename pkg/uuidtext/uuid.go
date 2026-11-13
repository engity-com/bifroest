// Package uuidtext is the text boundary for Bifröst-owned UUIDs. Binary UUIDs,
// hashes, keys, external protocol fields and original evidence bytes are not
// transformed by this codec.
package uuidtext

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
)

// Format always writes the canonical Base58 encoding of the UUID's 16 bytes.
func Format(value [16]byte) string { return base58.Encode(value[:]) }

// Classic is reserved for conversion output, historical signed formats and
// external protocols which require the conventional UUID notation.
func Classic(value [16]byte) string { return uuid.UUID(value).String() }

// OrderKey is a fixed-width binary ordering key, not an identifier notation.
// Base58 strings must not be compared lexically for UUID-ordered pagination.
func OrderKey(value [16]byte) string { return hex.EncodeToString(value[:]) }

// Parse accepts canonical Base58 and the established UUID notations. Entity
// policies (nil, version, variant) remain the caller's responsibility.
func Parse(text string) ([16]byte, error) {
	var result [16]byte
	classic := len(text) == 32 || len(text) == 36 ||
		len(text) == 38 && text[0] == '{' && text[37] == '}' ||
		len(text) == 45 && strings.EqualFold(text[:9], "urn:uuid:")
	if classic {
		parsed, err := uuid.Parse(text)
		if err != nil {
			return result, fmt.Errorf("invalid UUID notation: %w", err)
		}
		return [16]byte(parsed), nil
	}
	if len(text) < 16 || len(text) > 22 {
		return result, fmt.Errorf("invalid UUID text length")
	}
	data, err := base58.Decode(text)
	if err != nil || len(data) != len(result) {
		return result, fmt.Errorf("invalid Base58 UUID")
	}
	copy(result[:], data)
	if Format(result) != text {
		return [16]byte{}, fmt.Errorf("non-canonical Base58 UUID")
	}
	return result, nil
}

func Equal(left, right string) bool {
	a, err := Parse(left)
	if err != nil {
		return false
	}
	b, err := Parse(right)
	return err == nil && a == b
}

func Normalize(text string) (string, error) {
	value, err := Parse(text)
	if err != nil {
		return "", err
	}
	return Format(value), nil
}
