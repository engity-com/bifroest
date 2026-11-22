package authorization

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/template"
)

type evaluationWrapperRequestBase interface {
	PublicKeyRequest
	InteractiveRequest
}

// Only context/field access is implemented. Any accidental credential, session,
// transport or login operation panics through the nil interface embed.
type evaluationPlainTestRequest struct {
	evaluationWrapperRequestBase
	ctx context.Context
}

func (this evaluationPlainTestRequest) Context() context.Context { return this.ctx }
func (evaluationPlainTestRequest) GetField(name string) (any, bool, error) {
	if name == "marker" {
		return "request", true, nil
	}
	return nil, false, fmt.Errorf("unknown request field")
}

type evaluationScopedTestRequest struct {
	evaluationPlainTestRequest
	evaluation *template.Evaluation
}

func (this evaluationScopedTestRequest) TemplateEvaluation() *template.Evaluation {
	return this.evaluation
}

func TestAuthorizationWrappersRetainTemplateEvaluation(t *testing.T) {
	const key = "BIFROEST_AUTHORIZATION_WRAPPER_TEST"
	t.Setenv(key, "host sentinel")
	for _, test := range []struct {
		name string
		wrap func(evaluationWrapperRequestBase) any
	}{
		{"remote name", func(req evaluationWrapperRequestBase) any { return remoteNameRequest{req} }},
		{"primary public key", func(req evaluationWrapperRequestBase) any { return primaryPublicKeyRequest{req} }},
		{"remembered SSH", func(req evaluationWrapperRequestBase) any { return sshSessionResumeRequest{PublicKeyRequest: req} }},
		{"resume public key", func(req evaluationWrapperRequestBase) any { return resumePublicKeyRequest{Request: req} }},
		{"bounded OIDC code", func(req evaluationWrapperRequestBase) any {
			return &oidcCodeRequest{InteractiveRequest: req, ctx: req.Context()}
		}},
		{"OIDC login message", func(req evaluationWrapperRequestBase) any { return &oidcLoginMessageContext{request: req} }},
		{"composed requests", func(req evaluationWrapperRequestBase) any {
			return remoteNameRequest{primaryPublicKeyRequest{resumePublicKeyRequest{Request: req}}}
		}},
		{"composed login message", func(req evaluationWrapperRequestBase) any {
			return &oidcLoginMessageContext{request: &oidcCodeRequest{InteractiveRequest: req, ctx: req.Context()}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := template.MustNewString(fmt.Sprintf(`{{ env %q }}`, key))
			plain := evaluationPlainTestRequest{ctx: t.Context()}
			actual, err := value.Render(test.wrap(plain))
			require.NoError(t, err)
			require.Equal(t, "host sentinel", actual)
			ctx := evaluationScopedTestRequest{evaluationPlainTestRequest: plain, evaluation: template.NewEvaluation(template.EvaluationSources{
				LookupEnv: func(string) (string, bool, error) { return "fixture", true, nil },
			})}
			actual, err = value.Render(test.wrap(ctx))
			require.NoError(t, err)
			require.Equal(t, "fixture", actual)
			ctx.evaluation = template.NewEvaluation(template.EvaluationSources{})
			actual, err = value.Render(test.wrap(ctx))
			require.ErrorIs(t, err, template.ErrFunctionUnavailable)
			require.Empty(t, actual)
			ctx.evaluation = nil
			actual, err = value.Render(test.wrap(ctx))
			require.ErrorIs(t, err, template.ErrEvaluationUnavailable)
			require.Empty(t, actual)
		})
	}
}

func TestRemoteNameAndOidcMessageUseScopedSourcesThroughDerivedContexts(t *testing.T) {
	ctx := evaluationScopedTestRequest{evaluationPlainTestRequest: evaluationPlainTestRequest{ctx: t.Context()}, evaluation: template.NewEvaluation(template.EvaluationSources{
		LookupEnv: func(string) (string, bool, error) { return "fixture", true, nil },
	})}
	mapping := template.MustNewString(`{{ env "VALUE" }}`)
	name, err := resolveRemoteName(ctx, mapping)
	require.NoError(t, err)
	require.Equal(t, "fixture", name)
	boundedContext, cancel := context.WithCancel(t.Context())
	defer cancel()
	bounded := &oidcCodeRequest{InteractiveRequest: ctx, ctx: boundedContext}
	configured := template.MustNewString(`{{ .marker }}:{{ env "VALUE" }}:{{ .code }}`)
	message, err := RenderOidcSshLoginMessage(bounded, configured, "https://fixture.invalid", "test-code", true)
	require.NoError(t, err)
	require.Equal(t, "request:fixture:test-code", message)
	require.Same(t, boundedContext, bounded.Context())
	cancel()
	require.ErrorIs(t, bounded.Context().Err(), context.Canceled)

	ctx.evaluation = template.NewEvaluation(template.EvaluationSources{})
	name, err = resolveRemoteName(ctx, mapping)
	require.EqualError(t, err, "cannot evaluate authorization remoteName")
	require.Empty(t, name)
	message, err = RenderOidcSshLoginMessage(ctx, configured, "https://fixture.invalid/private-ticket", "private-code", true)
	require.EqualError(t, err, "cannot render SSH login message")
	require.Empty(t, message)
}

func TestExportedRemoteNameResolverRetainsProductionSemantics(t *testing.T) {
	ctx := evaluationScopedTestRequest{evaluationPlainTestRequest: evaluationPlainTestRequest{ctx: t.Context()}, evaluation: template.NewEvaluation(template.EvaluationSources{})}
	for _, source := range []string{"alice", `{{ .marker }}-account`, `{{ env "PRIVATE_VALUE" }}`, "invalid account name"} {
		mapping := template.MustNewString(source)
		expected, expectedErr := resolveRemoteName(ctx, mapping)
		actual, actualErr := ResolveRemoteName(ctx, mapping)
		require.Equal(t, expected, actual)
		if expectedErr != nil {
			require.EqualError(t, actualErr, expectedErr.Error())
		} else {
			require.NoError(t, actualErr)
		}
	}
	bounded, cancel := context.WithCancel(t.Context())
	cancel()
	ctx.ctx = bounded
	_, err := ResolveRemoteName(ctx, template.MustNewString("alice"))
	require.ErrorIs(t, err, context.Canceled)
}
