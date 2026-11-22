package environment

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestTargetProjectionPreservesTypesWithoutSensitiveCauses(t *testing.T) {
	for _, category := range []berrors.Type{berrors.Unknown, berrors.System, berrors.Config, berrors.Network, berrors.User, berrors.Permission, berrors.Expired} {
		t.Run(category.String(), func(t *testing.T) {
			secret := category.Newf("sensitive-provider-details")
			secret.UserFacing = true
			ctx := projectionEvaluationTestContext{
				targetTestContext: targetTestContext{ctx: t.Context()},
				evaluation: template.NewEvaluation(template.EvaluationSources{
					LookupEnv: func(string) (string, bool, error) { return "", false, fmt.Errorf("sensitive wrapper: %w", secret) },
				}),
			}
			for _, render := range []struct {
				name  string
				apply func(*configuration.EnvironmentDocker)
			}{
				{"string", func(conf *configuration.EnvironmentDocker) { conf.Image = template.MustNewString(`{{ env "SECRET" }}`) }},
				{"list", func(conf *configuration.EnvironmentDocker) {
					conf.Volumes = template.MustNewStrings(`{{ env "SECRET" }}`)
				}},
				{"bool", func(conf *configuration.EnvironmentDocker) {
					conf.Privileged = template.MustNewBool(`{{ env "SECRET" }}`)
				}},
			} {
				t.Run(render.name, func(t *testing.T) {
					conf := &configuration.EnvironmentDocker{}
					require.NoError(t, conf.SetDefaults())
					render.apply(conf)
					projection, err := ProjectDockerTarget(ctx, conf, DockerTargetMetadata{Backend: "unix:///fixture.sock"})
					typed, ok := berrors.IsError(err)
					require.True(t, ok)
					require.Equal(t, category, typed.Type)
					require.False(t, typed.UserFacing)
					require.NotContains(t, err.Error(), "sensitive")
					require.NotContains(t, fmt.Sprintf("%#v", typed), "sensitive")
					require.False(t, errors.Is(err, secret))
					require.Nil(t, errors.Unwrap(err), "redaction must discard the original cause, not just its message")
					require.Equal(t, TargetProjection{}, projection)
				})
			}
		})
	}
}

func TestTargetProjectionRetainsOnlySafeCancellationCauses(t *testing.T) {
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		secret := berrors.System.Newf("sensitive: %w", sentinel)
		err := sessionTargetError(berrors.Config, secret, "cannot resolve target")
		require.ErrorIs(t, err, sentinel)
		require.True(t, berrors.System.IsErr(err))
		require.NotContains(t, err.Error(), "sensitive")
		require.True(t, errors.Unwrap(err) == sentinel)
		require.False(t, errors.Is(err, secret))
	}
}
