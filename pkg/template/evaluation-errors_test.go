package template

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestEvaluationClassifiesItsOwnErrors(t *testing.T) {
	for _, test := range []struct {
		name, source string
		context      any
		sentinel     error
		category     berrors.Type
	}{
		{"missing scope", "{{ . }}", evaluationTestContext{}, ErrEvaluationUnavailable, berrors.System},
		{"cyclic scope", "{{ . }}", evaluationCyclicParentTestContext{}, ErrEvaluationUnavailable, berrors.System},
		{"unbound function", "{{ env }}", evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{})}, ErrFunctionUnavailable, berrors.Config},
		{"nested unbound function", `{{ firstMatching "{{ env }}" (list "ignored") }}`, evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{})}, ErrFunctionUnavailable, berrors.Config},
		{"invalid reader", `{{ file "fixture" }}`, evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{OpenFile: func(string) (io.ReadCloser, error) { return nil, nil }})}, ErrInvalidEvaluationSource, berrors.System},
		{"invalid stat", `{{ stat "fixture" }}`, evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{StatFile: func(string) (fs.FileInfo, error) { return nil, nil }})}, ErrInvalidEvaluationSource, berrors.System},
		{"policy failure", `{{ fail "policy failed" }}`, evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{})}, nil, berrors.Config},
		{"invalid function arguments", `{{ stat "illegal" "fixture" }}`, evaluationTestContext{evaluation: NewEvaluation(EvaluationSources{StatFile: func(string) (fs.FileInfo, error) { panic("invalid arguments must not access a source") }})}, nil, berrors.Config},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := MustNewString(test.source).Render(test.context)
			require.Error(t, err)
			require.True(t, test.category.IsErr(err), "%v", err)
			if test.sentinel != nil {
				require.ErrorIs(t, err, test.sentinel)
			}
		})
	}
}

func TestEvaluationPreservesSourceErrorTypesAndSentinels(t *testing.T) {
	for _, upstream := range []error{
		errors.New("untyped source failure"), context.Canceled, context.DeadlineExceeded,
		berrors.Unknown.Newf("unknown source failure"), berrors.Config.Newf("missing fixture fact"),
		berrors.System.Newf("system failure"), berrors.Network.Newf("network failure"),
		berrors.User.Newf("user failure"), berrors.Permission.Newf("permission failure"), berrors.Expired.Newf("expired failure"),
	} {
		expected := berrors.System
		if typed, ok := berrors.IsError(upstream); ok {
			expected = typed.Type
		}
		evaluation := NewEvaluation(EvaluationSources{
			LookupEnv: func(string) (string, bool, error) { return "", false, upstream },
			OpenFile:  func(string) (io.ReadCloser, error) { return nil, upstream },
			StatFile:  func(string) (fs.FileInfo, error) { return nil, upstream },
			Now:       func() (time.Time, error) { return time.Time{}, upstream },
		})
		for _, source := range []string{
			`{{ env "VALUE" }}`, `{{ expandenv "$VALUE" }}`, `{{ file "optional" "fixture" }}`,
			`{{ stat "optional" "fixture" }}`, `{{ fileExists "fixture" }}`, `{{ dirExists "fixture" }}`, `{{ now }}`,
			`{{ firstMatching "{{ env \"VALUE\" }}" (list "ignored") }}`,
		} {
			t.Run(upstream.Error()+"/"+source, func(t *testing.T) {
				_, err := MustNewString(source).Render(evaluationTestContext{evaluation: evaluation})
				require.ErrorIs(t, err, upstream)
				typed, ok := berrors.IsError(err)
				require.True(t, ok)
				require.Equal(t, expected, typed.Type)
			})
		}
	}
}

func TestEvaluationClassifiesReadFailuresAndRetainsOptionalAbsence(t *testing.T) {
	upstream := errors.New("reader failed")
	evaluation := NewEvaluation(EvaluationSources{
		OpenFile: func(string) (io.ReadCloser, error) {
			return io.NopCloser(evaluationTestErrorReader{err: upstream}), nil
		},
	})
	_, err := MustNewString(`{{ file "fixture" }}`).Render(evaluationTestContext{evaluation: evaluation})
	require.ErrorIs(t, err, upstream)
	require.True(t, berrors.System.IsErr(err))
	for _, absent := range []error{fs.ErrNotExist, &fs.PathError{Op: "open", Path: "fixture", Err: fs.ErrNotExist}} {
		evaluation := NewEvaluation(EvaluationSources{
			OpenFile: func(string) (io.ReadCloser, error) { return nil, absent },
			StatFile: func(string) (fs.FileInfo, error) { return nil, absent },
		})
		for _, source := range []string{`{{ file "optional" "fixture" }}`, `{{ stat "optional" "fixture" }}`, `{{ fileExists "fixture" }}`} {
			_, err := MustNewString(source).Render(evaluationTestContext{evaluation: evaluation})
			require.NoError(t, err, "%s: %s", fmt.Sprint(absent), source)
		}
	}
}
