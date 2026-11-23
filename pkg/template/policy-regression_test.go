package template

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestPolicyRegressionTypedTemplateRendering(t *testing.T) {
	data := map[string]any{"value": "42", "nil": nil, "empty": "", "flag": false}
	for _, test := range []struct {
		name string
		run  func() (any, error)
		want any
	}{
		{"string", func() (any, error) { return MustNewString(`{{ .value }}`).Render(data) }, "42"},
		{"bool", func() (any, error) { return MustNewBool(`{{ .value }}`).Render(data) }, true},
		{"int64", func() (any, error) { return MustNewInt64(`{{ .value }}`).Render(data) }, int64(42)},
		{"uint64", func() (any, error) { return MustNewUint64(`{{ .value }}`).Render(data) }, uint64(42)},
		{"duration", func() (any, error) { return MustNewDuration(`{{ .value }}s`).Render(data) }, 42 * time.Second},
		{"URL", func() (any, error) {
			v, err := MustNewUrl(`https://example.invalid/{{ .value }}`).Render(data)
			if err != nil {
				return nil, err
			}
			return v.String(), nil
		}, "https://example.invalid/42"},
		{"marshaller", func() (any, error) {
			return MustNewTextMarshaller[time.Time](`2026-11-20T10:00:{{ .value }}Z`).Render(data)
		}, time.Date(2026, 11, 20, 10, 0, 42, 0, time.UTC)},
		{"list", func() (any, error) { return MustNewStrings(`{{ .value }}`, `{{ .value }}s`).Render(data) }, []string{"42", "42s"}},
		{"nil and false", func() (any, error) { return MustNewString(`{{ .nil }}|{{ .empty }}|{{ .flag }}`).Render(data) }, "||false"},
		{"named template", func() (any, error) {
			return MustNewString(`{{ define "inner" }}{{ .value }}{{ end }}{{ template "inner" . }}`).Render(data)
		}, "42"},
	} {
		t.Run(test.name, func(t *testing.T) { got, err := test.run(); require.NoError(t, err); require.Equal(t, test.want, got) })
	}
	for _, run := range []func() error{
		func() error { _, err := MustNewString(`{{ .missing }}`).Render(data); return err },
		func() error { _, err := MustNewBool(`{{ .missing }}`).Render(data); return err },
		func() error { _, err := MustNewInt64(`{{ .missing }}`).Render(data); return err },
		func() error { _, err := MustNewUint64(`{{ .missing }}`).Render(data); return err },
		func() error { _, err := MustNewDuration(`{{ .missing }}`).Render(data); return err },
		func() error { _, err := MustNewUrl(`https://example.invalid/{{ .missing }}`).Render(data); return err },
		func() error { _, err := MustNewTextMarshaller[time.Time](`{{ .missing }}`).Render(data); return err },
	} {
		require.Error(t, run())
	}
	tmpl, err := NewTemplate("characterization", `{{ .nil }}|{{ .flag }}|{{ .value }}`)
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, tmpl.Execute(&output, data))
	require.Equal(t, "|false|42", output.String())
}

func TestPolicyRegressionProductionMatchingAndEnvironment(t *testing.T) {
	const key = "BIFROEST_CHARACTERIZATION_ENV"
	t.Setenv(key, "host-value")
	t.Setenv("BIFROEST_CHARACTERIZATION_ENV_EMPTY", "")
	t.Setenv("BIFROEST_CHARACTERIZATION_ENV_ABSENT", "temporary") // Register restoration before making this test key absent.
	require.NoError(t, os.Unsetenv("BIFROEST_CHARACTERIZATION_ENV_ABSENT"))
	for source, want := range map[string]string{
		`{{ env "BIFROEST_CHARACTERIZATION_ENV_EMPTY" "fallback" }}`:                            "",
		`{{ env "BIFROEST_CHARACTERIZATION_ENV_ABSENT" "first" "ignored" }}`:                    "first",
		`{{ env "BIFROEST_CHARACTERIZATION_ENV" }}`:                                             "host-value",
		`{{ env "BIFROEST_CHARACTERIZATION_ENV" "fallback" }}`:                                  "host-value",
		`{{ expandenv "$BIFROEST_CHARACTERIZATION_ENV" }}`:                                      "host-value",
		`{{ firstMatching "{{ . }}" (list "false" "0" "" "off" "no" "<nil>" "first" "last") }}`: "first",
		`{{ lastMatching "{{ . }}" (list "first" "false" "last" "off") }}`:                      "last",
		`{{ firstMatching "{{ . }}" (list "False" "ignored") }}`:                                "False",
		`{{ firstMatching "{{ env \"BIFROEST_CHARACTERIZATION_ENV\" }}" (list "ignored") }}`:    "host-value",
		`{{ lastMatching "{{ env \"BIFROEST_CHARACTERIZATION_ENV\" }}" (list "ignored") }}`:     "host-value",
		`{{ firstMatching "{{ . }}" (list "false" "off") }}`:                                    "",
	} {
		t.Run(source, func(t *testing.T) {
			value, err := MustNewString(source).Render(nil)
			require.NoError(t, err)
			require.Equal(t, want, value)
		})
	}
	value, err := firstMatching("{{ . }}", [2]string{"first", "last"})
	require.NoError(t, err)
	require.Equal(t, "first", value)
	value, err = lastMatching("{{ . }}", [2]string{"first", "last"})
	require.NoError(t, err)
	require.Equal(t, "last", value)
	for _, test := range []struct {
		name  string
		match func(string, any) (string, error)
		fails bool
	}{{"first short-circuits", firstMatching, false}, {"last reaches later error", lastMatching, true}} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.match(`{{ if eq . "bad" }}{{ fail "reached" }}{{ else }}{{ . }}{{ end }}`, []string{"first", "bad"})
			if test.fails {
				require.ErrorContains(t, err, "reached")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPolicyRegressionFileAndStatSemantics(t *testing.T) {
	dir := t.TempDir()
	name, absent := filepath.Join(dir, "fixture"), filepath.Join(dir, "absent")
	require.NoError(t, os.WriteFile(name, []byte("contents"), 0600))
	got, err := file(name)
	require.NoError(t, err)
	require.Equal(t, "contents", got)
	got, err = file("optional", absent)
	require.NoError(t, err)
	require.Empty(t, got)
	got, err = file("optional", "")
	require.NoError(t, err)
	require.Empty(t, got)
	info, err := stat(name)
	require.NoError(t, err)
	require.Equal(t, int64(8), info.Size())
	info, err = stat("optional", absent)
	require.NoError(t, err)
	require.Nil(t, info)
	for _, test := range []struct {
		path      string
		file, dir bool
	}{{name, true, false}, {dir, false, true}, {absent, false, false}} {
		isFile, err := fileExists(test.path)
		require.NoError(t, err)
		require.Equal(t, test.file, isFile)
		isDir, err := dirExists(test.path)
		require.NoError(t, err)
		require.Equal(t, test.dir, isDir)
	}
	_, err = file(absent)
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = stat(absent)
	require.ErrorIs(t, err, fs.ErrNotExist)
	large := filepath.Join(dir, "large")
	require.NoError(t, os.WriteFile(large, []byte(strings.Repeat("x", maximumReadFileSize+1)), 0600))
	got, err = file(large)
	require.NoError(t, err)
	require.Len(t, got, maximumReadFileSize)
}

// Invalid arguments are configuration errors; file and stat failures are system
// errors. Categorization must not discard an existing upstream category or cause.
func TestPolicyRegressionTemplateErrorCategories(t *testing.T) {
	for _, test := range []struct {
		name     string
		run      func() error
		category berrors.Type
	}{
		{"matching parse", func() error { _, err := firstMatching("{{", []string{"x"}); return err }, berrors.Config},
		{"matching input", func() error { _, err := lastMatching("{{ . }}", 42); return err }, berrors.Config},
		{"matching evaluation", func() error { _, err := firstMatching(`{{ fail "failure" }}`, []string{"x"}); return err }, berrors.Config},
		{"file option", func() error { _, err := file("invalid", "fixture"); return err }, berrors.Config},
		{"file missing name", func() error { _, err := file(""); return err }, berrors.Config},
		{"stat missing name", func() error { _, err := stat(""); return err }, berrors.Config},
		{"file missing path", func() error { _, err := file(filepath.Join(t.TempDir(), "absent")); return err }, berrors.System},
		{"stat missing path", func() error { _, err := stat(filepath.Join(t.TempDir(), "absent")); return err }, berrors.System},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			require.Error(t, err)
			typed, categorized := berrors.IsError(err)
			require.True(t, categorized)
			require.Equal(t, test.category, typed.Type)
		})
	}
}

type policyRegressionTemplateFailure struct{ err error }

func (this policyRegressionTemplateFailure) GetField(string) (any, bool, error) {
	return nil, false, this.err
}

func TestPolicyRegressionTemplateHelpersPreserveUpstreamErrorCategories(t *testing.T) {
	for _, category := range []berrors.Type{berrors.Unknown, berrors.Config, berrors.System, berrors.Network, berrors.User, berrors.Permission, berrors.Expired} {
		t.Run(category.String(), func(t *testing.T) {
			upstream := category.Newf("controlled failure")
			for _, test := range []struct {
				name string
				run  func() error
			}{
				{"firstMatching", func() error {
					_, err := firstMatching(`{{ .failure }}`, []any{policyRegressionTemplateFailure{err: upstream}})
					return err
				}},
				{"lastMatching", func() error {
					_, err := lastMatching(`{{ .failure }}`, []any{policyRegressionTemplateFailure{err: upstream}})
					return err
				}},
				{"file", func() error {
					_, err := fileWith(func(string) (io.ReadCloser, error) { return nil, upstream }, "fixture")
					return err
				}},
				{"stat", func() error {
					_, err := statWith(func(string) (fs.FileInfo, error) { return nil, upstream }, "fixture")
					return err
				}},
			} {
				t.Run(test.name, func(t *testing.T) {
					err := test.run()
					require.ErrorIs(t, err, upstream)
					typed, ok := berrors.IsError(err)
					require.True(t, ok)
					require.Equal(t, category, typed.Type)
				})
			}
		})
	}
}
