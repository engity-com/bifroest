package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/template"
)

type localEvaluationTestRequest struct {
	localTemplateTestRequest
	evaluation *template.Evaluation
}

func (this localEvaluationTestRequest) TemplateEvaluation() *template.Evaluation {
	return this.evaluation
}

func TestLocalTemplateContextRetainsEvaluationAndCandidateData(t *testing.T) {
	const key = "BIFROEST_LOCAL_TEMPLATE_WRAPPER_TEST"
	t.Setenv(key, "host sentinel")
	value := template.MustNewString(`{{ .authorization.name }}:{{ .user.name }}:{{ .user.managed }}:{{ env "BIFROEST_LOCAL_TEMPLATE_WRAPPER_TEST" }}`)
	plain := localTemplateContext{Request: localTemplateTestRequest{}, user: localTemplateTestAccount{}, managed: true}
	actual, err := value.Render(plain)
	require.NoError(t, err)
	require.Equal(t, "remote-user:local-user:true:host sentinel", actual)
	root := localEvaluationTestRequest{evaluation: template.NewEvaluation(template.EvaluationSources{
		LookupEnv: func(string) (string, bool, error) { return "fixture", true, nil },
	})}
	for _, wrap := range []func(Request) Request{
		func(parent Request) Request { return parent },
		func(parent Request) Request { return localTemplateContext{Request: parent} },
	} {
		derived := localTemplateContext{Request: wrap(root), user: localTemplateTestAccount{}, managed: false}
		actual, err := value.Render(derived)
		require.NoError(t, err)
		require.Equal(t, "remote-user:local-user:false:fixture", actual)
	}
	for _, evaluation := range []*template.Evaluation{nil, template.NewEvaluation(template.EvaluationSources{})} {
		root.evaluation = evaluation
		_, err := value.Render(localTemplateContext{Request: root, user: localTemplateTestAccount{}})
		if evaluation == nil {
			require.ErrorIs(t, err, template.ErrEvaluationUnavailable)
		} else {
			require.ErrorIs(t, err, template.ErrFunctionUnavailable)
		}
	}
}
