package management

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
)

func TestManagementMetricsRejectsMalformedSSHResponses(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot model.MetricsSnapshot
	}{
		{"nil-family", model.MetricsSnapshot{Families: []*dto.MetricFamily{nil}}},
		{"nil-metric", model.MetricsSnapshot{Families: []*dto.MetricFamily{{Name: proto.String("test_metric"), Type: dto.MetricType_GAUGE.Enum(), Metric: []*dto.Metric{nil}}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, done := managementClientTestServer(t, transport.WireCommand, func(channel ssh.Channel, args []string) error {
				if !slices.Equal(args, []string{"metrics", "show", "--", "test_metric"}) {
					return fmt.Errorf("unexpected metrics request %v", args)
				}
				encoded, err := transport.EncodeWireResult(test.snapshot)
				if err != nil {
					return err
				}
				if _, err := channel.Write(encoded); err != nil {
					return err
				}
				_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return err
			})
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
			snapshot, err := target.Metrics(ctx, []string{"test_metric"})
			require.ErrorContains(t, err, "invalid metrics snapshot")
			require.Equal(t, model.MetricsSnapshot{}, snapshot)
			require.Empty(t, output.Bytes())
			require.NoError(t, <-done)
		})
	}
}
