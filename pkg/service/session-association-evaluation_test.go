package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type associationEvaluationTestContext struct {
	associationAdapterContext
	evaluation *template.Evaluation
}

func (this associationEvaluationTestContext) TemplateEvaluation() *template.Evaluation {
	return this.evaluation
}

func TestAssociationDerivedContextsRetainTemplateEvaluation(t *testing.T) {
	const key = "BIFROEST_ASSOCIATION_WRAPPER_TEST"
	t.Setenv(key, "host.example")
	plain := associationAdapter(t, "request-user", bconn.TransportSsh)
	bounded, cancel := context.WithCancel(t.Context())
	defer cancel()
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString(`{{ env "BIFROEST_ASSOCIATION_WRAPPER_TEST" }}`)
	conf.User = template.MustNewString("account")
	for _, test := range []struct {
		name string
		wrap func(environment.Context) environment.Context
	}{
		{"target", func(base environment.Context) environment.Context {
			return newAssociationTargetContext(bounded, base, session.Reference{Flow: "candidate-flow"})
		}},
		{"candidate", func(base environment.Context) environment.Context {
			return &associationCandidateContext{associationBaseContext: base, ctx: bounded, auth: base.Authorization()}
		}},
		{"composed", func(base environment.Context) environment.Context {
			base = newAssociationTargetContext(bounded, base, session.Reference{Flow: "candidate-flow"})
			return &associationCandidateContext{associationBaseContext: base, ctx: bounded, auth: base.Authorization()}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := template.MustNewString(`{{ env "BIFROEST_ASSOCIATION_WRAPPER_TEST" }}:{{ .remote.user }}`)
			actual, err := value.Render(test.wrap(plain))
			require.NoError(t, err)
			require.Equal(t, "host.example:request-user", actual)
			base := associationEvaluationTestContext{associationAdapterContext: plain, evaluation: template.NewEvaluation(template.EvaluationSources{
				LookupEnv: func(string) (string, bool, error) { return "fixture.example", true, nil },
			})}
			derived := test.wrap(base)
			actual, err = value.Render(derived)
			require.NoError(t, err)
			require.Equal(t, "fixture.example:request-user", actual)
			require.Same(t, bounded, derived.Context(), "scope lookup must not replace the candidate's bounded context")
			projection, err := environment.ProjectSshTarget(derived, conf)
			require.NoError(t, err)
			address, present := projection.Field("address")
			require.True(t, present)
			require.Equal(t, "fixture.example:22", address)
			for _, evaluation := range []*template.Evaluation{nil, template.NewEvaluation(template.EvaluationSources{})} {
				base.evaluation = evaluation
				derived = test.wrap(base)
				actual, err = value.Render(derived)
				if evaluation == nil {
					require.ErrorIs(t, err, template.ErrEvaluationUnavailable)
				} else {
					require.ErrorIs(t, err, template.ErrFunctionUnavailable)
				}
				require.Empty(t, actual)
				_, err = environment.ProjectSshTarget(derived, conf)
				require.EqualError(t, err, "cannot resolve session target field address")
			}
		})
	}
}
