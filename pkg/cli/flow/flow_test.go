package flow

import (
	"bytes"
	"context"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestManagementFlowUsesReusableDefinitionAndInvocationAccess(t *testing.T) {
	requirement := cli.NewSimpleApplication().WithName("bifroest").WithFallbackToStdio(false).WithErrorHandlerEnabled(false)
	Register(t.Context(), requirement, common.UsageManagement)
	app, err := requirement.Create()
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "admin", Environment: configuration.Environment{V: &configuration.EnvironmentManagement{}},
	}}}
	for _, test := range []struct {
		args    []string
		expects string
	}{
		{[]string{"flow", "ls", "--format=json"}, `"name":"admin"`},
		{[]string{"flow", "show", "admin"}, "environment.type"},
		{[]string{"flow", "ls"}, "NAME"},
	} {
		var output, diagnostic bytes.Buffer
		ctx := common.ContextWithManagementAccess(context.Background(), common.ManagementAccess{Configuration: conf})
		ctx = cli.ContextWithStdio(ctx, nil, &output, &diagnostic)
		require.NoError(t, app.ParseAndExecute(ctx, nil, test.args...))
		require.Contains(t, output.String(), test.expects)
		require.Empty(t, diagnostic.String())
	}
	var output, diagnostic bytes.Buffer
	ctx := cli.ContextWithStdio(common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{Configuration: conf}), nil, &output, &diagnostic)
	require.Error(t, app.ParseAndExecute(ctx, nil, "flow", "ls", "--configuration=server.yaml"))
	require.Empty(t, output.String())
}
