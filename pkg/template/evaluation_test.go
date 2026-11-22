package template

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"
)

type evaluationTestContext struct {
	evaluation *Evaluation
	fields     map[string]any
}

func (this evaluationTestContext) TemplateEvaluation() *Evaluation { return this.evaluation }
func (this evaluationTestContext) GetField(name string) (any, bool, error) {
	value, present := this.fields[name]
	return value, present, nil
}

func TestEvaluationFunctionInventoryIsComplete(t *testing.T) {
	seen := make(map[string]bool)
	for _, group := range evaluationFunctionGroups {
		require.NotEqual(t, evaluationFunctionUnknown, group.kind)
		for _, name := range strings.Fields(group.names) {
			require.False(t, seen[name], "function %s has duplicate classifications", name)
			seen[name] = true
			require.Contains(t, allFuncs, name, "inventory contains a function absent from the production registry")
		}
	}
	evaluation := NewEvaluation(EvaluationSources{})
	for name, function := range allFuncs {
		require.True(t, seen[name], "unclassified function %s requires dependency review", name)
		require.Contains(t, evaluation.functions, name)
		if evaluationFunctionKinds[name] == evaluationFunctionLocal {
			require.Equal(t, reflect.ValueOf(function).Pointer(), reflect.ValueOf(evaluation.functions[name]).Pointer(),
				"local function %s must retain its production implementation", name)
		}
	}
	require.Equal(t, len(allFuncs), len(evaluation.functions))
	t.Logf("inventoried %d production functions", len(allFuncs))
}

func TestEvaluationDeniesEveryUnboundFunctionWithoutExecutingIt(t *testing.T) {
	ctx := evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{})}
	for name := range allFuncs {
		if evaluationFunctionKinds[name] == evaluationFunctionLocal || name == "firstMatching" || name == "lastMatching" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			// The variadic denial stub must run instead of the original function,
			// even before any arguments are supplied to DNS, random or key APIs.
			value, err := MustNewString("{{ " + name + " }}").Render(ctx)
			require.ErrorIs(t, err, ErrFunctionUnavailable)
			require.Contains(t, err.Error(), name)
			require.Empty(t, value)
		})
	}
}

func TestEvaluationPreservesLocalFunctionAndTemplateSemantics(t *testing.T) {
	fields := map[string]any{
		"value":   "alice@example.org@remotehost",
		"nested":  map[string]any{"empty": nil},
		"instant": time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
	}
	ctx := evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{}), fields: fields}
	for _, source := range []string{
		`{{ regexReplaceAll "@[^@]+$" .value "" }}`,
		`{{ list "second" "first" | sortAlpha | join "," }}`,
		`{{ dict "enabled" false "count" 42 | toJson }}`,
		`{{ $d := dict "one" 1 }}{{ $_ := set $d "two" 2 }}{{ $d | toJson }}`,
		`{{ semverCompare ">=1.0.0" "1.2.3" }}`,
		`{{ .value | sha256sum | trunc 16 }}`,
		`{{ .nested.empty }}`,
		`{{ or .nested.empty "fallback" }}`,
		`{{ dateModify "1h" .instant | unixEpoch }}`,
		`{{ .instant | format "dateOnly" }}`,
		`{{ pathJoin "one" "two" ".." "three" }}`,
		`{{ firstMatching "{{.}}" (list "false" "0" "" "off" "no" "<nil>" "chosen" "later") }}`,
		`{{ lastMatching "{{.}}" (list "false" "chosen" "later" "no") }}`,
	} {
		t.Run(source, func(t *testing.T) {
			value := MustNewString(source)
			expected, err := value.Render(fields)
			require.NoError(t, err)
			actual, err := value.Render(ctx)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
	for _, source := range []string{
		`{{ .nested.missing }}`,
		`{{ mustRegexFind "[" .value }}`,
		`{{ fail "expected policy error" }}`,
		`{{ firstMatching "{{" (list "ignored") }}`,
		`{{ lastMatching "{{.}}" 42 }}`,
	} {
		t.Run(source, func(t *testing.T) {
			value := MustNewString(source)
			_, expected := value.Render(fields)
			require.Error(t, expected)
			_, actual := value.Render(ctx)
			require.EqualError(t, actual, expected.Error())
		})
	}
}

var errEvaluationTestFactMissing = errors.New("fixture fact was not modeled")

func evaluationTestSources() EvaluationSources {
	fixed := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	files := fstest.MapFS{
		"fixture":   &fstest.MapFile{Data: []byte("fixture contents"), Mode: 0640, ModTime: fixed},
		"directory": &fstest.MapFile{Mode: fs.ModeDir | 0750, ModTime: fixed},
	}
	knownPath := func(name string) bool { return name == "fixture" || name == "directory" || name == "absent" }
	return EvaluationSources{
		LookupEnv: func(key string) (string, bool, error) {
			switch key {
			case "SET":
				return "fixture value", true, nil
			case "EMPTY":
				return "", true, nil
			case "ABSENT":
				return "", false, nil
			default:
				return "", false, errEvaluationTestFactMissing
			}
		},
		OpenFile: func(name string) (io.ReadCloser, error) {
			if !knownPath(name) {
				return nil, errEvaluationTestFactMissing
			}
			return files.Open(name)
		},
		StatFile: func(name string) (fs.FileInfo, error) {
			if !knownPath(name) {
				return nil, errEvaluationTestFactMissing
			}
			return fs.Stat(files, name)
		},
		Now: func() (time.Time, error) { return fixed, nil },
	}
}

func TestEvaluationSourcesPreserveAbsentEmptyAndOptionalSemantics(t *testing.T) {
	ctx := evaluationTestContext{evaluation: NewEvaluation(evaluationTestSources())}
	for source, expected := range map[string]string{
		`{{ env "SET" }}`:                           "fixture value",
		`{{ env "EMPTY" "fallback" }}`:              "",
		`{{ env "ABSENT" }}`:                        "",
		`{{ env "ABSENT" "fallback" "ignored" }}`:   "fallback",
		`{{ expandenv "${SET}/$EMPTY/${ABSENT}" }}`: "fixture value//",
		`{{ file "fixture" }}`:                      "fixture contents",
		`{{ file "optional" "absent" }}`:            "",
		`{{ file "optional" "" }}`:                  "",
		`{{ (stat "fixture").Size }}`:               "16",
		`{{ (stat "fixture").Mode }}`:               "-rw-r-----",
		`{{ stat "optional" "absent" }}`:            "",
		`{{ fileExists "fixture" }}`:                "true",
		`{{ fileExists "directory" }}`:              "false",
		`{{ fileExists "absent" }}`:                 "false",
		`{{ dirExists "fixture" }}`:                 "false",
		`{{ dirExists "directory" }}`:               "true",
		`{{ dirExists "absent" }}`:                  "false",
		`{{ now | unixEpoch }}`:                     strconv.FormatInt(time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC).Unix(), 10),
	} {
		t.Run(source, func(t *testing.T) {
			actual, err := MustNewString(source).Render(ctx)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
	for _, source := range []string{
		`{{ env "unmodeled" "fallback" }}`,
		`{{ expandenv "$SET/$unmodeled" }}`,
		`{{ file "optional" "unmodeled" }}`,
		`{{ stat "optional" "unmodeled" }}`,
		`{{ fileExists "unmodeled" }}`,
		`{{ dirExists "unmodeled" }}`,
	} {
		t.Run(source, func(t *testing.T) {
			value, err := MustNewString(source).Render(ctx)
			require.ErrorIs(t, err, errEvaluationTestFactMissing)
			require.Empty(t, value)
		})
	}
	for _, source := range []string{`{{ file "absent" }}`, `{{ stat "absent" }}`} {
		_, err := MustNewString(source).Render(ctx)
		require.ErrorIs(t, err, fs.ErrNotExist)
	}
	for _, source := range []string{`{{ file "invalid-option" "fixture" }}`, `{{ stat "invalid-option" "fixture" }}`} {
		_, err := MustNewString(source).Render(ctx)
		require.ErrorContains(t, err, "illegal optional")
	}
}

func TestEvaluationMatchingAndNamedTemplatesRetainTheirScope(t *testing.T) {
	ctx := evaluationTestContext{evaluation: NewEvaluation(evaluationTestSources())}
	for _, helper := range []string{"firstMatching", "lastMatching"} {
		for _, nested := range []string{`{{ env "SET" }}`, `{{ file "fixture" }}`} {
			source := fmt.Sprintf(`{{ %s %q (list "ignored") }}`, helper, nested)
			actual, err := MustNewString(source).Render(ctx)
			require.NoError(t, err)
			expected, err := MustNewString(nested).Render(ctx)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		}
		for _, nested := range []string{`{{ getHostByName "example.invalid" }}`, `{{ randAlphaNum 8 }}`, `{{ env "SET" }}`} {
			source := fmt.Sprintf(`{{ %s %q (list "ignored") }}`, helper, nested)
			value, err := MustNewString(source).Render(evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{})})
			require.ErrorIs(t, err, ErrFunctionUnavailable)
			require.Empty(t, value)
		}
	}
	inner := fmt.Sprintf(`{{ lastMatching %q (list "ignored") }}`, `{{ env "SET" }}`)
	value, err := MustNewString(fmt.Sprintf(`{{ firstMatching %q (list "ignored") }}`, inner)).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "fixture value", value)
	value, err = MustNewString(`{{ define "child" }}{{ env "SET" }}{{ end }}{{ template "child" . }}`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "fixture value", value)

	// The list element's own capability cannot replace the caller's scope.
	ctx.fields = map[string]any{"items": []any{evaluationTestContext{}}}
	value, err = MustNewString(`{{ firstMatching "{{ env \"SET\" }}" .items }}`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "fixture value", value)
	// Unreached dependencies must not be evaluated preemptively.
	value, err = MustNewString(`{{ if false }}{{ getHostByName "example.invalid" }}{{ else }}kept{{ end }}`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "kept", value)
}

func TestEvaluationHasNoHostFallbackAndDoesNotChangeProductionTemplates(t *testing.T) {
	const key = "BIFROEST_CONTROLLED_TEMPLATE_TEST"
	t.Setenv(key, "host sentinel")
	filename := filepath.Join(t.TempDir(), "host-file")
	require.NoError(t, os.WriteFile(filename, []byte("host contents"), 0600))
	for _, source := range []string{
		fmt.Sprintf(`{{ env %q "fallback" }}`, key),
		fmt.Sprintf(`{{ expandenv %q }}`, "${"+key+"}"),
		fmt.Sprintf(`{{ file "optional" %q }}`, filename),
		fmt.Sprintf(`{{ stat "optional" %q }}`, filename),
		fmt.Sprintf(`{{ fileExists %q }}`, filename),
		fmt.Sprintf(`{{ dirExists %q }}`, filepath.Dir(filename)),
		fmt.Sprintf(`{{ firstMatching %q (list "ignored") }}`, fmt.Sprintf(`{{ env %q }}`, key)),
	} {
		t.Run(source, func(t *testing.T) {
			value := MustNewString(source)
			expected, err := value.Render(nil)
			require.NoError(t, err)
			require.NotEmpty(t, expected)
			actual, err := value.Render(evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{})})
			require.ErrorIs(t, err, ErrFunctionUnavailable)
			require.Empty(t, actual)
			actual, err = value.Render(reflect.ValueOf(evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{})}))
			require.ErrorIs(t, err, ErrFunctionUnavailable, "reflect.Value must not discard the evaluation capability")
			require.Empty(t, actual)
			again, err := value.Render(nil)
			require.NoError(t, err)
			require.Equal(t, expected, again, "controlled execution must not mutate the parsed production template")
		})
	}
	for _, evaluation := range []*Evaluation{nil, {}} {
		_, err := MustNewString(fmt.Sprintf(`{{ env %q }}`, key)).Render(evaluationTestContext{evaluation: evaluation})
		require.ErrorIs(t, err, ErrEvaluationUnavailable)
	}
	var typedNil *evaluationTestContext
	_, err := MustNewString(fmt.Sprintf(`{{ env %q }}`, key)).Render(typedNil)
	require.ErrorIs(t, err, ErrEvaluationUnavailable)
}

func TestEvaluationCoversEveryTypedRenderPath(t *testing.T) {
	ctx := evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{LookupEnv: func(string) (string, bool, error) {
		return "42", true, nil
	}})}
	text, err := MustNewString(`{{ env "VALUE" }}`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "42", text)
	boolean, err := MustNewBool(`{{ env "VALUE" }}`).Render(ctx)
	require.NoError(t, err)
	require.True(t, boolean)
	integer, err := MustNewInt64(`{{ env "VALUE" }}`).Render(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 42, integer)
	unsigned, err := MustNewUint64(`{{ env "VALUE" }}`).Render(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 42, unsigned)
	interval, err := MustNewDuration(`{{ env "VALUE" }}s`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, 42*time.Second, interval)
	address, err := MustNewUrl(`https://example.invalid/{{ env "VALUE" }}`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "https://example.invalid/42", address.String())
	marshaled, err := MustNewTextMarshaller[time.Time](`2026-11-20T10:00:{{ env "VALUE" }}Z`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 11, 20, 10, 0, 42, 0, time.UTC), marshaled)
	list, err := MustNewStrings(`{{ env "VALUE" }}`, `{{ env "VALUE" }}s`).Render(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"42", "42s"}, list)
	enforced, flag, err := MustNewEnforceable[Duration](`!{{ env "VALUE" }}s`).Render(ctx)
	require.NoError(t, err)
	require.True(t, flag)
	require.Equal(t, 42*time.Second, enforced)

	ctx.evaluation = NewEvaluation(EvaluationSources{})
	for _, render := range []func(any) error{
		func(data any) error { _, err := MustNewString(`{{ env "VALUE" }}`).Render(data); return err },
		func(data any) error { _, err := MustNewBool(`{{ env "VALUE" }}`).Render(data); return err },
		func(data any) error { _, err := MustNewInt64(`{{ env "VALUE" }}`).Render(data); return err },
		func(data any) error { _, err := MustNewUint64(`{{ env "VALUE" }}`).Render(data); return err },
		func(data any) error { _, err := MustNewDuration(`{{ env "VALUE" }}s`).Render(data); return err },
		func(data any) error {
			_, err := MustNewUrl(`https://example.invalid/{{ env "VALUE" }}`).Render(data)
			return err
		},
		func(data any) error {
			_, err := MustNewTextMarshaller[time.Time](`{{ env "VALUE" }}`).Render(data)
			return err
		},
		func(data any) error { _, err := MustNewStrings(`{{ env "VALUE" }}`).Render(data); return err },
		func(data any) error {
			_, _, err := MustNewEnforceable[Duration](`!{{ env "VALUE" }}s`).Render(data)
			return err
		},
	} {
		require.ErrorIs(t, render(ctx), ErrFunctionUnavailable)
	}
}

func TestEvaluationsOfTheSameParsedTemplateAreIndependent(t *testing.T) {
	value := MustNewString(`{{ .principal }}:{{ env "VALUE" }}:{{ firstMatching "{{ env \"VALUE\" }}" (list "ignored") }}`)
	for i := range 16 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			principal := fmt.Sprintf("principal-%d", i)
			sources := EvaluationSources{LookupEnv: func(string) (string, bool, error) { return principal, true, nil }}
			evaluation := NewEvaluation(sources)
			sources.LookupEnv = func(string) (string, bool, error) { panic("constructor must copy callback values") }
			ctx := evaluationTestContext{evaluation: evaluation, fields: map[string]any{"principal": principal}}
			for range 5 {
				actual, err := value.Render(ctx)
				require.NoError(t, err)
				require.Equal(t, strings.Repeat(principal+":", 2)+principal, actual)
			}
		})
	}
}

type evaluationTestFile struct {
	io.Reader
	closed bool
}

func (this *evaluationTestFile) Close() error { this.closed = true; return nil }

func TestEvaluationFileReadsRetainTheProductionLimitAndCloseTheSource(t *testing.T) {
	reader := &evaluationTestFile{Reader: strings.NewReader(strings.Repeat("x", maximumReadFileSize+1))}
	ctx := evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{
		OpenFile: func(string) (io.ReadCloser, error) { return reader, nil },
	})}
	value, err := MustNewString(`{{ file "fixture" }}`).Render(ctx)
	require.NoError(t, err)
	require.Len(t, value, maximumReadFileSize)
	require.True(t, reader.closed)
}

type evaluationTestNilInfo struct{ fs.FileInfo }

type evaluationTestErrorReader struct{ err error }

func (this evaluationTestErrorReader) Read([]byte) (int, error) { return 0, this.err }

func TestEvaluationRejectsInvalidSourcesAndClosesFailedReads(t *testing.T) {
	for _, source := range []EvaluationSources{
		{OpenFile: func(string) (io.ReadCloser, error) { return nil, nil }},
		{OpenFile: func(string) (io.ReadCloser, error) { return (*evaluationTestFile)(nil), nil }},
		{StatFile: func(string) (fs.FileInfo, error) { return nil, nil }},
		{StatFile: func(string) (fs.FileInfo, error) { return (*evaluationTestNilInfo)(nil), nil }},
	} {
		ctx := evaluationTestContext{evaluation: NewEvaluation(source)}
		function := `{{ file "optional" "fixture" }}`
		if source.StatFile != nil {
			function = `{{ stat "optional" "fixture" }}`
		}
		value, err := MustNewString(function).Render(ctx)
		require.ErrorIs(t, err, ErrInvalidEvaluationSource)
		require.Empty(t, value)
	}
	for _, failOnOpen := range []bool{false, true} {
		reader := &evaluationTestFile{Reader: evaluationTestErrorReader{errEvaluationTestFactMissing}}
		ctx := evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{
			OpenFile: func(string) (io.ReadCloser, error) {
				if failOnOpen {
					return reader, errEvaluationTestFactMissing
				}
				return reader, nil
			},
		})}
		value, err := MustNewString(`{{ file "optional" "fixture" }}`).Render(ctx)
		require.ErrorIs(t, err, errEvaluationTestFactMissing)
		require.Empty(t, value)
		require.True(t, reader.closed, "owned readers must be closed on both source and read errors")
	}
}

func TestEvaluationSourcesAreLazyAndTheirErrorsStopEvaluation(t *testing.T) {
	calls := 0
	sources := EvaluationSources{
		LookupEnv: func(string) (string, bool, error) { calls++; return "", false, errEvaluationTestFactMissing },
		Now:       func() (time.Time, error) { calls++; return time.Time{}, errEvaluationTestFactMissing },
	}
	ctx := evaluationTestContext{evaluation: NewEvaluation(sources)}
	require.Zero(t, calls, "constructing a function scope must not call its sources")
	_, err := MustNewString(`{{ expandenv "$first/$second" }}`).Render(ctx)
	require.ErrorIs(t, err, errEvaluationTestFactMissing)
	require.Equal(t, 1, calls, "expansion must stop looking up facts after the first error")
	_, err = MustNewString(`{{ now }}`).Render(ctx)
	require.ErrorIs(t, err, errEvaluationTestFactMissing)
	require.Equal(t, 2, calls)
}
