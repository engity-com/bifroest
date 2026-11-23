package template

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

type evaluationParentTestContext struct {
	parent any
	marker string
}

func (this evaluationParentTestContext) TemplateEvaluationParent() any { return this.parent }
func (this evaluationParentTestContext) GetField(name string) (any, bool, error) {
	if name == "marker" {
		return this.marker, true, nil
	}
	if fields, ok := this.parent.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return fields.GetField(name)
	}
	return nil, false, fmt.Errorf("unknown derived field")
}

type evaluationOverrideParentTestContext struct {
	evaluationParentTestContext
	evaluation *Evaluation
}

func (this evaluationOverrideParentTestContext) TemplateEvaluation() *Evaluation {
	return this.evaluation
}

func TestEvaluationContextParentsKeepScopesAndDerivedData(t *testing.T) {
	sources := evaluationTestSources()
	root := evaluationTestContext{evaluation: NewEvaluation(sources), fields: map[string]any{"marker": "root"}}
	for _, data := range []any{
		evaluationParentTestContext{parent: root, marker: "derived"},
		evaluationParentTestContext{parent: evaluationParentTestContext{parent: root, marker: "inner"}, marker: "derived"},
		evaluationParentTestContext{parent: reflect.ValueOf(root), marker: "derived"},
		reflect.ValueOf(evaluationParentTestContext{parent: root, marker: "derived"}),
	} {
		value, err := MustNewString(`{{ .marker }}:{{ env "SET" }}:{{ firstMatching "{{ env \"SET\" }}" (list "ignored") }}`).Render(data)
		require.NoError(t, err)
		require.Equal(t, "derived:fixture value:fixture value", value, "only the function scope, not execution data, comes from the parent")
	}
	// An explicit scope overrides its parent, rather than merging providers.
	value, err := MustNewString(`{{ env "SET" }}`).Render(evaluationOverrideParentTestContext{
		evaluationParentTestContext: evaluationParentTestContext{parent: root},
		evaluation: NewEvaluation(EvaluationSources{LookupEnv: func(string) (string, bool, error) {
			return "override", true, nil
		}}),
	})
	require.NoError(t, err)
	require.Equal(t, "override", value)
	for _, evaluation := range []*Evaluation{nil, {}, NewEvaluation(EvaluationSources{})} {
		_, err := MustNewString(`{{ env "SET" }}`).Render(evaluationOverrideParentTestContext{
			evaluationParentTestContext: evaluationParentTestContext{parent: root}, evaluation: evaluation,
		})
		if evaluation != nil && evaluation.functions != nil {
			require.ErrorIs(t, err, ErrFunctionUnavailable)
		} else {
			require.ErrorIs(t, err, ErrEvaluationUnavailable)
		}
	}
}

type evaluationCyclicParentTestContext struct{ data []any }

func (this evaluationCyclicParentTestContext) TemplateEvaluationParent() any { return this }

func TestEvaluationContextParentsFailClosedOnInvalidChains(t *testing.T) {
	const key = "BIFROEST_EVALUATION_PARENT_TEST"
	t.Setenv(key, "host sentinel")
	root := evaluationTestContext{evaluation: NewEvaluation(evaluationTestSources())}
	var deepest any = root
	for range maximumEvaluationContextDepth - 1 {
		deepest = evaluationParentTestContext{parent: deepest}
	}
	value, err := MustNewString(`{{ env "SET" }}`).Render(deepest)
	require.NoError(t, err)
	require.Equal(t, "fixture value", value)
	for _, parent := range []any{
		evaluationParentTestContext{parent: deepest},
		evaluationCyclicParentTestContext{data: []any{"uncomparable"}},
		(*evaluationParentTestContext)(nil),
		evaluationParentTestContext{parent: (*evaluationTestContext)(nil)},
		evaluationParentTestContext{parent: evaluationTestContext{}},
	} {
		value, err := MustNewString(fmt.Sprintf(`{{ env %q }}`, key)).Render(parent)
		require.ErrorIs(t, err, ErrEvaluationUnavailable)
		require.Empty(t, value)
		require.NotContains(t, err.Error(), "uncomparable")
	}
}

func TestEvaluationContextParentsPreserveUnscopedProductionBehavior(t *testing.T) {
	const key = "BIFROEST_UNSCOPED_PARENT_TEST"
	t.Setenv(key, "host value")
	for _, parent := range []any{nil, struct{}{}, evaluationParentTestContext{}} {
		value, err := MustNewString(fmt.Sprintf(`{{ env %q }}`, key)).Render(evaluationParentTestContext{parent: parent})
		require.NoError(t, err)
		require.Equal(t, "host value", value, "forwarding a parent must not implicitly opt production into controlled evaluation")
	}
}

func TestEvaluationContextParentsIsolateParallelDerivedContexts(t *testing.T) {
	value := MustNewString(`{{ .marker }}:{{ env "SET" }}`)
	root := evaluationTestContext{evaluation: NewEvaluation(evaluationTestSources())}
	for i := range 16 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			marker := strconv.Itoa(i)
			ctx := evaluationParentTestContext{parent: root, marker: marker}
			for range 5 {
				actual, err := value.Render(ctx)
				require.NoError(t, err)
				require.Equal(t, marker+":fixture value", actual)
			}
		})
	}
}
