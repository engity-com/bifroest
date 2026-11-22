package template

import (
	"reflect"

	"github.com/engity-com/bifroest/pkg/errors"
)

// EvaluationContextParent lets a derived context forward its original template
// evaluation capability without wrapping or replacing the data being rendered.
// It is not itself an opt-in to controlled execution: an unscoped parent retains
// production behavior. A direct EvaluationContext takes precedence, including
// when it explicitly returns nil or a zero Evaluation.
//
// The parent is used only to find the function scope. Data fields, context
// deadlines and other optional capabilities still come from the derived data.
// Implementations must forward their actual parent, not a reconstructed view.
type EvaluationContextParent interface {
	TemplateEvaluationParent() any
}

const maximumEvaluationContextDepth = 64

func evaluationFrom(data any) (*Evaluation, bool, error) {
	for range maximumEvaluationContextDepth {
		// Match the underlying engine's reflect.Value support without losing
		// the original context's capability. Execution data stays unchanged.
		if value, ok := data.(reflect.Value); ok && value.IsValid() && value.CanInterface() {
			data = value.Interface()
		}
		if ctx, ok := data.(EvaluationContext); ok {
			if isNilEvaluationValue(ctx) {
				return nil, false, ErrEvaluationUnavailable
			}
			return ctx.TemplateEvaluation(), true, nil
		}
		if parent, ok := data.(EvaluationContextParent); ok {
			if isNilEvaluationValue(parent) {
				return nil, false, ErrEvaluationUnavailable
			}
			data = parent.TemplateEvaluationParent()
			continue
		}
		return nil, false, nil
	}
	// Bound malformed, cyclic or freshly recreated parent chains without
	// guessing that they are unscoped and falling back to host functions.
	return nil, false, errors.System.Newf("%w: cyclic or overly deep template evaluation context", ErrEvaluationUnavailable)
}
