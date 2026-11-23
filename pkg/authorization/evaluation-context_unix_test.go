//go:build unix

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalUserRequestRetainsTemplateEvaluation(t *testing.T) {
	ctx := evaluationScopedTestRequest{evaluationPlainTestRequest: evaluationPlainTestRequest{ctx: t.Context()}, evaluation: template.NewEvaluation(template.EvaluationSources{
		LookupEnv: func(string) (string, bool, error) { return "fixture", true, nil },
	})}
	account := &user.User{Name: "synthetic-user", Uid: 1234}
	value := template.MustNewString(`{{ .user.name }}:{{ env "VALUE" }}`)
	actual, err := value.Render(&userEnabledRequest{Request: ctx, user: account})
	require.NoError(t, err)
	require.Equal(t, "synthetic-user:fixture", actual)
	ctx.evaluation = template.NewEvaluation(template.EvaluationSources{})
	_, err = value.Render(&userEnabledRequest{Request: ctx, user: account})
	require.ErrorIs(t, err, template.ErrFunctionUnavailable)
}
