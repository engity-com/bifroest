package uuidtext

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllUUIDNotationsHaveOneBase58Writer(t *testing.T) {
	for range 200 {
		var value [16]byte
		_, err := rand.Read(value[:])
		require.NoError(t, err)
		base := Format(value)
		classic := Classic(value)
		for _, text := range []string{base, classic, strings.ToUpper(classic), strings.ReplaceAll(classic, "-", ""), "{" + classic + "}", "urn:uuid:" + classic} {
			parsed, err := Parse(text)
			require.NoError(t, err)
			require.Equal(t, value, parsed)
			normalized, err := Normalize(text)
			require.NoError(t, err)
			require.Equal(t, base, normalized)
			require.True(t, Equal(text, base))
		}
	}
	zero := [16]byte{}
	require.Equal(t, "1111111111111111", Format(zero))
	parsed, err := Parse(Format(zero))
	require.NoError(t, err)
	require.Equal(t, zero, parsed)
}

func TestUUIDTextDoesNotAcceptMalformedOrVariableWidthIdentities(t *testing.T) {
	for _, text := range []string{"", " ", "ABCDEF1", strings.Repeat("1", 15), strings.Repeat("1", 17), strings.Repeat("z", 22), "0OIl1111111111111111", " 00000000-0000-0000-0000-000000000000", "[00000000-0000-0000-0000-000000000000]", "00000000-0000-0000-0000-000000000000\n"} {
		_, err := Parse(text)
		require.Error(t, err, text)
	}
}

func FuzzUUIDText(f *testing.F) {
	f.Add("34e34ab8-7457-4d88-a5e4-c57791775c3a")
	f.Add("1111111111111111")
	f.Add("not-an-id")
	f.Fuzz(func(t *testing.T, text string) {
		value, err := Parse(text)
		if err != nil {
			return
		}
		again, err := Parse(Format(value))
		require.NoError(t, err)
		require.Equal(t, value, again)
	})
}
