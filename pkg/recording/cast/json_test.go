package cast

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCastEventStringCapacity(t *testing.T) {
	// Test integer arithmetic only; no boundary-sized strings or allocations.
	for _, test := range []struct {
		name             string
		length, expected int
	}{
		{"empty", 0, 2},
		{"ascii", 64, 66},
		{"before-last-safe", math.MaxInt - 3, math.MaxInt - 1},
		{"last-safe", math.MaxInt - 2, math.MaxInt},
		{"first-fallback", math.MaxInt - 1, math.MaxInt - 1},
		{"maximum", math.MaxInt, math.MaxInt},
		{"negative-one", -1, -1},
		{"negative-two", -2, -2},
		{"minimum", math.MinInt, math.MinInt},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, castEventStringCapacity(test.length))
		})
	}
}

func TestMarshalCastEventStringCanonicalEscaping(t *testing.T) {
	for _, test := range []struct{ input, expected string }{
		{"", `""`},
		{"terminal <>& / output", `"terminal <>& / output"`},
		{"\"\\\b\f\n\r\t\x00\x1b", `"\"\\\b\f\n\r\t\u0000\u001b"`},
		{"Grüße ☃\u00a0\u2028\u2029\U000e0001", `"Grüße ☃\u00a0\u2028\u2029\udb40\udc01"`},
		{"\xff\xc0\x80", "\"���\""},
	} {
		t.Run(test.expected, func(t *testing.T) {
			require.Equal(t, test.expected, string(marshalCastEventString(test.input)))
		})
	}
}

var benchmarkCastEventString []byte

func BenchmarkCastEventString(b *testing.B) {
	for _, test := range []struct{ name, value string }{
		{"ascii-64", strings.Repeat("x", 64)},
		{"ascii-4096", strings.Repeat("x", 4096)},
		{"ascii-65536", strings.Repeat("x", 65536)},
		{"terminal", strings.Repeat("\x1b[32mGrüße ☃\x1b[0m\r\n", 128)},
		{"escapes", strings.Repeat("\"\\\x00\u00a0\u2028\U000e0001", 128)},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.Run("canonical", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(test.value)))
				for b.Loop() {
					benchmarkCastEventString = marshalCastEventString(test.value)
				}
			})
			// Cost reference only: encoding/json has different HTML/Unicode
			// escaping and is not a byte-compatible canonical Cast encoder.
			b.Run("stdlib-reference", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(test.value)))
				for b.Loop() {
					var err error
					benchmarkCastEventString, err = json.Marshal(test.value)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
