package recording

import (
	"unicode"
	"unicode/utf16"
)

const lowerHex = "0123456789abcdef"

func marshalCastEventString(value string) []byte {
	result := make([]byte, 0, len(value)+2)
	result = append(result, '"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			result = append(result, '\\', byte(character))
		case '\b':
			result = append(result, '\\', 'b')
		case '\f':
			result = append(result, '\\', 'f')
		case '\n':
			result = append(result, '\\', 'n')
		case '\r':
			result = append(result, '\\', 'r')
		case '\t':
			result = append(result, '\\', 't')
		default:
			if mustEscapeCastCodePoint(character) {
				if character <= 0xffff {
					result = appendCastUnicodeEscape(result, uint16(character))
				} else {
					high, low := utf16.EncodeRune(character)
					result = appendCastUnicodeEscape(result, uint16(high))
					result = appendCastUnicodeEscape(result, uint16(low))
				}
			} else {
				result = append(result, string(character)...)
			}
		}
	}
	return append(result, '"')
}

func mustEscapeCastCodePoint(value rune) bool {
	return !unicode.IsPrint(value) || value == '\u2028' || value == '\u2029'
}

func appendCastUnicodeEscape(target []byte, value uint16) []byte {
	return append(target,
		'\\', 'u',
		lowerHex[value>>12],
		lowerHex[value>>8&0xf],
		lowerHex[value>>4&0xf],
		lowerHex[value&0xf],
	)
}
