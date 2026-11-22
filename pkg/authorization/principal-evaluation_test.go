package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

type principalEvaluationTestContext struct {
	*principalMappingTestContext
	evaluation *template.Evaluation
}

func (this principalEvaluationTestContext) TemplateEvaluation() *template.Evaluation {
	return this.evaluation
}

func TestAuthenticationWithPrincipalRetainsTemplateEvaluation(t *testing.T) {
	auth := newPrincipalMappingTestOidc()
	flows := principalMappingTestFlows(`{{ .authorization.userInfo.preferred_username }}-{{ firstMatching "{{ env \"SUFFIX\" }}" (list "ignored") }}`)
	for _, test := range []struct {
		name       string
		evaluation *template.Evaluation
		err        error
	}{
		{"explicit source", template.NewEvaluation(template.EvaluationSources{
			LookupEnv: func(string) (string, bool, error) { return "fixture", true, nil },
		}), nil},
		{"unbound source", template.NewEvaluation(template.EvaluationSources{}), template.ErrFunctionUnavailable},
		{"missing evaluation", nil, template.ErrEvaluationUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, err := AuthenticationWithPrincipal(auth, flows, func(unmapped authentication.Identity) PrincipalMappingContext {
				return principalEvaluationTestContext{
					principalMappingTestContext: newPrincipalMappingTestContext(t, unmapped, auth),
					evaluation:                  test.evaluation,
				}
			})
			if test.err != nil {
				require.ErrorIs(t, err, test.err)
				if test.err == template.ErrFunctionUnavailable {
					require.True(t, errors.Config.IsErr(err))
				} else {
					require.True(t, errors.System.IsErr(err))
				}
				require.Equal(t, authentication.Identity{}, identity)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "alice-fixture", identity.Principal)
			require.Equal(t, auth.identity.Issuer, identity.Issuer)
			require.Equal(t, auth.identity.Subject, identity.Subject)
			require.Equal(t, "subject-123", auth.identity.Principal)
		})
	}
}

func TestPrincipalMappingPreservesSourceErrorCategories(t *testing.T) {
	for _, category := range []errors.Type{errors.Unknown, errors.System, errors.Config, errors.Network, errors.User, errors.Permission, errors.Expired} {
		t.Run(category.String(), func(t *testing.T) {
			upstream := category.Newf("source failure")
			auth := newPrincipalMappingTestOidc()
			identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(`{{ env "PRINCIPAL" }}`), func(unmapped authentication.Identity) PrincipalMappingContext {
				return principalEvaluationTestContext{
					principalMappingTestContext: newPrincipalMappingTestContext(t, unmapped, auth),
					evaluation: template.NewEvaluation(template.EvaluationSources{
						LookupEnv: func(string) (string, bool, error) { return "", false, upstream },
					}),
				}
			})
			require.ErrorIs(t, err, upstream)
			typed, ok := errors.IsError(err)
			require.True(t, ok)
			require.Equal(t, category, typed.Type)
			require.Equal(t, authentication.Identity{}, identity)
		})
	}
}
