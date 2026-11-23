package environment

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

type projectionEvaluationTestContext struct {
	targetTestContext
	evaluation *template.Evaluation
}

func (this projectionEvaluationTestContext) TemplateEvaluation() *template.Evaluation {
	return this.evaluation
}

func TestTargetProjectionsUseTheCallersTemplateEvaluation(t *testing.T) {
	evaluation := template.NewEvaluation(template.EvaluationSources{
		LookupEnv: func(key string) (string, bool, error) {
			switch key {
			case "ADDRESS":
				return "WORK.EXAMPLE", true, nil
			case "IMAGE":
				return "fixture.invalid/approved:latest", true, nil
			case "NAMESPACE":
				return "fixture", true, nil
			case "FORWARDING":
				return "false", true, nil
			default:
				return "", false, fmt.Errorf("unmodeled environment fact")
			}
		},
		OpenFile: func(name string) (io.ReadCloser, error) {
			if name != "directory" {
				return nil, fmt.Errorf("unmodeled file fact")
			}
			return io.NopCloser(strings.NewReader("/workspace")), nil
		},
	})
	for _, test := range []struct {
		kind    string
		project func(*testing.T, Context) (TargetProjection, error)
		fields  map[string]any
	}{
		{"ssh", func(t *testing.T, ctx Context) (TargetProjection, error) {
			conf := &configuration.EnvironmentSsh{}
			require.NoError(t, conf.SetDefaults())
			conf.Address = template.MustNewString(`{{ env "ADDRESS" }}`)
			conf.User = template.MustNewString(`{{ .authentication.principal }}`)
			conf.PortForwardingAllowed = template.MustNewBool(`{{ env "FORWARDING" }}`)
			return ProjectSshTarget(ctx, conf)
		}, map[string]any{"address": "work.example:22", "user": "alice", "portForwardingAllowed": false}},
		{"docker", func(t *testing.T, ctx Context) (TargetProjection, error) {
			conf := &configuration.EnvironmentDocker{}
			require.NoError(t, conf.SetDefaults())
			conf.Image = template.MustNewString(`{{ firstMatching "{{ env \"IMAGE\" }}" (list "ignored") }}`)
			conf.User = template.MustNewString(`{{ .authentication.principal }}`)
			conf.Directory = template.MustNewString(`{{ file "directory" }}`)
			conf.PortForwardingAllowed = template.MustNewBool(`{{ env "FORWARDING" }}`)
			return ProjectDockerTarget(ctx, conf, DockerTargetMetadata{Backend: "unix:///fixture.sock", Os: sys.OsLinux, Arch: sys.ArchAmd64})
		}, map[string]any{"image": "fixture.invalid/approved:latest", "directory": "/workspace", "user": "alice", "portForwardingAllowed": false}},
		{"kubernetes", func(t *testing.T, ctx Context) (TargetProjection, error) {
			conf := &configuration.EnvironmentKubernetes{}
			require.NoError(t, conf.SetDefaults())
			conf.Namespace = template.MustNewString(`{{ env "NAMESPACE" }}`)
			conf.User = template.MustNewString(`{{ .authentication.principal }}`)
			conf.Directory = template.MustNewString(`{{ file "directory" }}`)
			return ProjectKubernetesTarget(ctx, conf, KubernetesTargetMetadata{Backend: "https://fixture.invalid", Namespace: "unused"})
		}, map[string]any{"namespace": "fixture", "directory": "/workspace", "user": "alice"}},
	} {
		t.Run(test.kind, func(t *testing.T) {
			ctx := projectionEvaluationTestContext{targetTestContext: targetTestContext{ctx: t.Context(), principal: "alice"}, evaluation: evaluation}
			projection, err := test.project(t, ctx)
			require.NoError(t, err)
			require.Equal(t, test.kind, projection.Kind())
			for name, expected := range test.fields {
				requireProjectionField(t, projection, name, expected)
			}
			_, err = projection.SessionTarget()
			require.NoError(t, err)
			ctx.evaluation = template.NewEvaluation(template.EvaluationSources{})
			projection, err = test.project(t, ctx)
			require.Error(t, err, "missing sources must not become an empty selector or backend fallback")
			require.Equal(t, TargetProjection{}, projection)
			require.NotContains(t, err.Error(), "unmodeled")
		})
	}
}
