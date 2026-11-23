package charts

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestChartIgnoreMatchesHelmRules(t *testing.T) {
	for _, test := range []struct {
		name, rules, file  string
		directory, ignored bool
	}{
		{"default-hidden-template", "", "templates/.hidden.yaml", false, true},
		{"default-visible-template", "", "templates/configmap.yaml", false, false},
		{"default-is-not-recursive", "", "templates/nested/.hidden.yaml", false, false},
		{"comments-bom-crlf", "\ufeff # comment\r\n\r\n  *.key \r\n", "templates/private.key", false, true},
		{"basename-at-root", "private.key", "private.key", false, true},
		{"basename-nested", "private.key", "templates/nested/private.key", false, true},
		{"basename-not-prefix", "private.key", "templates/private.key.yaml", false, false},
		{"anchored-root", "/private.key", "private.key", false, true},
		{"anchored-not-nested", "/private.key", "templates/private.key", false, false},
		{"structural-path", "templates/*.key", "templates/private.key", false, true},
		{"glob-not-recursive", "templates/*.key", "templates/nested/private.key", false, false},
		{"question-mark", "templates/secret?.yaml", "templates/secret1.yaml", false, true},
		{"character-class", "templates/secret[12].yaml", "templates/secret2.yaml", false, true},
		{"character-class-miss", "templates/secret[12].yaml", "templates/secret3.yaml", false, false},
		{"escaped-character", `templates/secret\?.yaml`, "templates/secret?.yaml", false, true},
		{"directory-basename", "scratch/", "templates/scratch", true, true},
		{"directory-not-file", "scratch/", "templates/scratch", false, false},
		{"anchored-directory", "/scratch/", "scratch", true, true},
		{"anchored-directory-not-nested", "/scratch/", "templates/scratch", true, false},
		{"structural-directory", "templates/scratch/", "templates/scratch", true, true},
		{"negation-nonmatch-ignored", "!keep.yaml", "templates/other.yaml", false, true},
		{"negation-match-continues", "!keep.yaml\nkeep.yaml", "templates/keep.yaml", false, true},
		{"negation-match-included", "!keep.yaml", "templates/keep.yaml", false, false},
		{"first-match-cannot-be-reincluded", "*.yaml\n!keep.yaml", "templates/keep.yaml", false, true},
		{"negative-directory-non-directory", "!scratch/", "scratch", false, true},
		{"negative-directory-matches", "!scratch/", "templates/scratch", true, false},
		{"negative-directory-misses", "!scratch/", "templates/other", true, true},
		{"negative-anchored-root", "!/keep.yaml", "templates/keep.yaml", false, true},
		{"root-cannot-be-ignored", "*", ".", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			rules, err := parseChartIgnore([]byte(test.rules))
			require.NoError(t, err)
			require.Equal(t, test.ignored, chartInputIgnored(rules, test.file, test.directory))
		})
	}
}

func TestChartIgnoreRejectsInvalidOrExcessiveRules(t *testing.T) {
	for name, raw := range map[string]string{
		"double-star":       "templates/**/secret.yaml",
		"bad-class":         "[",
		"bad-negated-class": "![",
		"bad-escape":        "templates/secret\\",
		"too-many-rules":    strings.Repeat("*.key\n", maxIgnoreRules+1),
		"excessive-line":    strings.Repeat("x", maxIgnoreFileSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseChartIgnore([]byte(raw))
			require.Error(t, err)
		})
	}
	// Comments and empty lines do not consume the rule budget.
	rules, err := parseChartIgnore([]byte(strings.Repeat("# comment\n\n*.key\n", maxIgnoreRules)))
	require.NoError(t, err)
	require.Len(t, rules, maxIgnoreRules+1, "the built-in Helm default is additional to user rules")
}

func TestChartIgnoreMustBeBoundedRegularAndUnlinked(t *testing.T) {
	for _, mode := range []fs.FileMode{fs.ModeSymlink, fs.ModeDir, fs.ModeNamedPipe, fs.ModeDevice} {
		t.Run(mode.String(), func(t *testing.T) {
			source := sourceChart()
			source[".helmignore"] = &fstest.MapFile{Data: []byte(".helmignore\n"), Mode: mode}
			_, err := Build(t.Context(), source, "1.2.3", testChartTime())
			require.ErrorContains(t, err, ".helmignore must be a regular, unlinked file")
		})
	}
	source := sourceChart()
	source[".helmignore"] = &fstest.MapFile{Data: []byte("#" + strings.Repeat("x", maxIgnoreFileSize-2) + "\n")}
	_, err := Build(t.Context(), source, "1.2.3", testChartTime())
	require.NoError(t, err, "an ignore file exactly at the size limit is accepted")
	source[".helmignore"].Data = append(source[".helmignore"].Data, '\n')
	_, err = Build(t.Context(), source, "1.2.3", testChartTime())
	require.ErrorContains(t, err, "exceeds size limit")
}
