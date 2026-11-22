package test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNamesAllowUnicodeWordsAndExactlyTheDeclaredPunctuation(t *testing.T) {
	for _, name := range []string{"ÄÖüß", "日本語", "Ελληνικά", "Кириллица", "العربية", "हिन्दी", "a\u0308", "１２３", ".,-_[]()%@!~=+", strings.Repeat("界", 80), strings.Repeat("𐐀", 80)} {
		t.Run(name, func(t *testing.T) {
			require.True(t, validName(name))
			source := strings.ReplaceAll(suiteSource(`t:IsEqual(true,true)`), `name="offline"`, `name=`+strconv.Quote(name))
			source = strings.ReplaceAll(source, `name="example"`, `name=`+strconv.Quote(name))
			report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
			require.Zero(t, report.ExitCode(), "%+v", report)
			var text strings.Builder
			require.NoError(t, report.WriteTextWithOptions(&text, TextOptions{Verbose: true}))
			require.Contains(t, text.String(), "--- PASS: "+name+" (")
			require.NotContains(t, text.String(), `"`+name+`"`)
		})
	}
	for _, r := range " \t\n\r/\\<>{}|`#$^&*:;?'\"😀©€\x00\x1b\x7f\u0085\u00a0\u200b\u200d\u202e\u2066\ufeff\u034f\ufe0f" {
		require.False(t, validName("before"+string(r)+"after"), "forbidden code point U+%04X", r)
	}
	for _, name := range []string{"", "bad\xff", strings.Repeat("a", 81), strings.Repeat("界", 81)} {
		require.False(t, validName(name))
	}
}

func TestInvalidNamesRemainErrorsEvenWhenCaughtOrUnselected(t *testing.T) {
	for _, field := range []string{`name="offline"`, `name="example"`} {
		source := strings.Replace(suiteSource(`t:IsEqual(true,true)`), field, `name="bad/name"`, 1)
		report := RunSourcesWithOptions(t.Context(), []byte(`pcall(function() `+source+` end)`), []byte(testConfiguration), Options{Includes: []string{"^none/"}})
		require.Equal(t, 2, report.ExitCode())
		require.Equal(t, "error", report.Results[0].Status)
	}
}
