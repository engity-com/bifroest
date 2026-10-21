package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfSession "github.com/engity-com/bifroest/pkg/session"
)

type testSessionControl struct {
	disconnect func(context.Context, bfSession.Id) (model.SessionActionResult, error)
	dispose    func(context.Context, bfSession.Id) (model.SessionActionResult, error)
}

func (this testSessionControl) Disconnect(ctx context.Context, id bfSession.Id) (model.SessionActionResult, error) {
	return this.disconnect(ctx, id)
}

func (this testSessionControl) Dispose(ctx context.Context, id bfSession.Id) (model.SessionActionResult, error) {
	return this.dispose(ctx, id)
}

func TestSessionControlUsesInvocationOperationsAndStreams(t *testing.T) {
	app := cli.NewSimpleApplication().WithName("bifroest").WithFallbackToStdio(false).WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).WithCommand(CreateCommands()...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	id := bfSession.MustNewId()
	for _, command := range []string{"disconnect", "dispose", "disconnect"} {
		var output, diagnostic bytes.Buffer
		called := false
		action := func(ctx context.Context, actual bfSession.Id) (model.SessionActionResult, error) {
			require.Equal(t, id, actual)
			require.Same(t, &output, cli.StdoutOfContext(ctx))
			called = true
			return model.SessionActionResult{ID: actual.String(), Flow: "workload", Action: command}, nil
		}
		control := testSessionControl{}
		if command == "dispose" {
			control.dispose = action
		} else {
			control.disconnect = action
		}
		ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{SessionControl: control})
		ctx = cli.ContextWithStdio(ctx, nil, &output, &diagnostic)
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}, "session", command, id.String(), "--format=json"))
		require.True(t, called)
		require.Empty(t, diagnostic.String())
		var result model.SessionActionResult
		require.NoError(t, json.Unmarshal(output.Bytes(), &result))
		require.Equal(t, command, result.Action)
		require.Equal(t, "workload", result.Flow)
	}
	for _, command := range []string{"disconnect", "dispose"} {
		for _, profile := range []string{common.ProfileExecutable, common.ProfileRemote, common.ProfileManagement} {
			var output bytes.Buffer
			ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
			require.Error(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{profile}}, "session", command, id.String()))
			require.Empty(t, output.String())
		}
	}
}

func TestSessionControlDoesNotPrintSuccessOnFailure(t *testing.T) {
	failure := errors.New("cleanup failed")
	for _, command := range []string{"disconnect", "dispose"} {
		var output bytes.Buffer
		action := func(context.Context, bfSession.Id) (model.SessionActionResult, error) {
			return model.SessionActionResult{Action: command}, failure
		}
		ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{SessionControl: testSessionControl{action, action}})
		ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
		opts := showOptions{Parent: &sessionOptions{}}
		require.ErrorIs(t, handleManagementAction(ctx, opts, command == "dispose"), failure)
		require.Empty(t, output.String())
	}
}

func TestSessionControlSeparatesConcurrentInvocations(t *testing.T) {
	app := cli.NewSimpleApplication().WithName("bifroest").WithFallbackToStdio(false).WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).WithCommand(CreateCommands()...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	const count = 12
	ids := make([]bfSession.Id, count)
	outputs := make([]bytes.Buffer, count)
	failures := make([]error, count)
	var group sync.WaitGroup
	for index := range ids {
		ids[index] = bfSession.MustNewId()
		group.Go(func() {
			command := "disconnect"
			if index%2 != 0 {
				command = "dispose"
			}
			action := func(_ context.Context, id bfSession.Id) (model.SessionActionResult, error) {
				return model.SessionActionResult{ID: id.String(), Flow: "workload", Action: command}, nil
			}
			ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{SessionControl: testSessionControl{action, action}})
			ctx = cli.ContextWithStdio(ctx, nil, &outputs[index], nil)
			failures[index] = app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}, "session", command, ids[index].String(), "--format=json")
		})
	}
	group.Wait()
	for index := range ids {
		require.NoError(t, failures[index])
		var result model.SessionActionResult
		require.NoError(t, json.Unmarshal(outputs[index].Bytes(), &result))
		require.Equal(t, ids[index].String(), result.ID)
		if index%2 == 0 {
			require.Equal(t, "disconnect", result.Action)
		} else {
			require.Equal(t, "dispose", result.Action)
		}
	}
}
