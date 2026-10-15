package management

import (
	"bytes"
	"sync"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/stretchr/testify/require"
)

func TestAuditEventFlagsBelongToManagementSchema(t *testing.T) {
	app, err := NewApplication(nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	var out bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &out, nil)
	require.NoError(t, app.ParseAndExecute(ctx, nil, "audit", "events", "--help"))
	require.Contains(t, out.String(), "--with-sensitive")
	require.Contains(t, out.String(), "--since")
}

func TestManagementApplicationSeparatesConcurrentInvocations(t *testing.T) {
	app, err := NewApplication(nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	const count = 12
	results := make([]string, count)
	failures := make([]error, count)
	var group sync.WaitGroup
	for index := range results {
		group.Add(1)
		go func() {
			defer group.Done()
			conf := &configuration.Configuration{Flows: configuration.Flows{{
				Name:        configuration.FlowName("flow-" + string(rune('a'+index))),
				Environment: configuration.Environment{V: &configuration.EnvironmentManagement{}},
			}}}
			var output bytes.Buffer
			ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{Configuration: conf})
			ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
			failures[index] = app.ParseAndExecute(ctx, nil, "flow", "ls", "--format=json")
			results[index] = output.String()
		}()
	}
	group.Wait()
	for index := range results {
		require.NoError(t, failures[index])
		require.Contains(t, results[index], "flow-"+string(rune('a'+index)))
	}
}

func TestManagementApplicationDoesNotShareCredentialDisclosure(t *testing.T) {
	app, err := NewApplication(nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, app.Close()) }()
	const secret = "invocation-only-credential"
	conf := &configuration.Configuration{Flows: configuration.Flows{{
		Name: "production", Environment: configuration.Environment{
			V: &configuration.EnvironmentDocker{ImagePullCredentials: template.MustNewString(secret)},
		},
	}}}
	for _, disclose := range []bool{false, true, false} {
		var output bytes.Buffer
		ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{
			Configuration: conf, IncludingCredentials: disclose,
		})
		ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
		require.NoError(t, app.ParseAndExecute(ctx, nil, "flow", "show", "production", "--format=json"))
		if disclose {
			require.Contains(t, output.String(), secret)
		} else {
			require.NotContains(t, output.String(), secret)
		}
	}
}
