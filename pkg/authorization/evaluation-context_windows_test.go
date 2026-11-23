//go:build windows

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func TestLocalUserRequestRetainsTemplateEvaluation(t *testing.T) {
	ctx := evaluationScopedTestRequest{evaluationPlainTestRequest: evaluationPlainTestRequest{ctx: t.Context()}, evaluation: template.NewEvaluation(template.EvaluationSources{
		LookupEnv: func(string) (string, bool, error) { return "fixture", true, nil },
	})}
	account := windowslocal.Account{Name: "synthetic-user", SID: "S-1-5-21-1-2-3-1001"}
	value := template.MustNewString(`{{ .user.name }}:{{ env "VALUE" }}`)
	actual, err := value.Render(&localUserRequest{Request: ctx, user: account})
	require.NoError(t, err)
	require.Equal(t, "synthetic-user:fixture", actual)
	ctx.evaluation = template.NewEvaluation(template.EvaluationSources{})
	_, err = value.Render(&localUserRequest{Request: ctx, user: account})
	require.ErrorIs(t, err, template.ErrFunctionUnavailable)
}
