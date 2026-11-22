//go:build unix

package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalUpdatePolicyRetainsTheRequestsTemplateEvaluation(t *testing.T) {
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.CreateIfAbsent = template.BoolOf(false)
	conf.UpdateIfDifferent = template.MustNewBool(`{{ and .user.managed (eq (env "UPDATE_ALLOWED") "fixture") }}`)
	repository := &LocalRepository{conf: conf}
	request := localEvaluationTestRequest{evaluation: template.NewEvaluation(template.EvaluationSources{
		LookupEnv: func(string) (string, bool, error) { return "fixture", true, nil },
	})}
	// This evaluates only existing policy decisions; no repository/provider,
	// account lookup, provisioning or process is available to the helper.
	opts, err := repository.getEnsureOptsOf(request, &user.User{Name: "synthetic-user", Uid: 1234}, true)
	require.NoError(t, err)
	require.False(t, opts.createIfAbsent)
	require.True(t, opts.updateIfDifferent)
	request.evaluation = template.NewEvaluation(template.EvaluationSources{})
	_, err = repository.getEnsureOptsOf(request, &user.User{Name: "synthetic-user", Uid: 1234}, true)
	require.ErrorIs(t, err, template.ErrFunctionUnavailable)
}
