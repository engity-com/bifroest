package metrics

import (
	"bytes"
	"context"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
)

type testMetrics struct {
	names []string
	calls int
}

func (this *testMetrics) Snapshot(_ context.Context, names []string) (model.MetricsSnapshot, error) {
	this.calls++
	this.names = append([]string{}, names...)
	return model.MetricsSnapshot{CapturedAt: time.Unix(100, 0).UTC(), ProcessStartedAt: time.Unix(10, 0).UTC()}, nil
}

func TestMetricsTypedFormatAndInvocation(t *testing.T) {
	app := cli.NewSimpleApplication().WithName("bifroest").WithFallbackToStdio(false).WithErrorHandlerEnabled(false).
		WithCommand(CreateCommands()...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	for _, test := range []struct {
		name string
		args []string
		wire bool
		want string
	}{
		{"default", nil, false, "METRIC"},
		{"table", []string{"--format=table"}, false, "METRIC"},
		{"json", []string{"--format=json"}, false, `"families":[]`},
		{"openmetrics", []string{"--format=openmetrics"}, false, "# EOF\n"},
		{"wire-default", nil, true, ""},
		{"wire-json", []string{"--format=json"}, true, ""},
		{"wire-openmetrics", []string{"--format=openmetrics"}, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			metrics := &testMetrics{}
			var output bytes.Buffer
			ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{Metrics: metrics, WireFormat: test.wire})
			ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
			args := append([]string{"metrics", "show", "first", "second"}, test.args...)
			require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}, args...))
			require.Equal(t, []string{"first", "second"}, metrics.names)
			require.Equal(t, 1, metrics.calls)
			if test.wire {
				var snapshot model.MetricsSnapshot
				require.NoError(t, transport.DecodeWireResult(bytes.NewReader(output.Bytes()), &snapshot))
				require.Equal(t, time.Unix(100, 0).UTC(), snapshot.CapturedAt)
			} else {
				require.Contains(t, output.String(), test.want)
			}
		})
	}
	for _, input := range []string{"yaml", "cbor", "openmetric", "internal-cbor", "internal-cbor-stream", "unknown"} {
		for _, wire := range []bool{false, true} {
			metrics := &testMetrics{}
			var output bytes.Buffer
			ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{Metrics: metrics, WireFormat: wire})
			ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
			require.Error(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}, "metrics", "show", "--format="+input))
			require.Zero(t, metrics.calls, "invalid format must fail before collecting metrics")
			require.Empty(t, output.Bytes())
		}
	}
}

func TestMetricsFormatForInvocation(t *testing.T) {
	for _, selected := range []format.MetricsFormat{format.MetricsText, format.MetricsJson, format.MetricsOpenMetrics} {
		require.Equal(t, selected, common.MetricsFormatForInvocation(t.Context(), selected))
		human := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{})
		require.Equal(t, selected, common.MetricsFormatForInvocation(human, selected))
		wire := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{WireFormat: true})
		require.Equal(t, format.MetricsWireCbor, common.MetricsFormatForInvocation(wire, selected))
	}
}
