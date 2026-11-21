package format

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	climodel "github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
)

func metricsFormatFixture(t *testing.T) climodel.MetricsSnapshot {
	t.Helper()
	registry := prometheus.NewRegistry()
	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_duration_seconds", Help: "Duration.", Buckets: []float64{1, 2}}, []string{"flow"})
	histogram.WithLabelValues("first\n\x1b[31m").Observe(0.5)
	histogram.WithLabelValues("second").Observe(3)
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_gauge", Help: "Non-finite values are valid samples."})
	gauge.Set(math.Inf(1))
	registry.MustRegister(histogram, gauge)
	families, err := registry.Gather()
	require.NoError(t, err)
	families = append(families, &dto.MetricFamily{
		Name: proto.String("test_summary"), Help: proto.String("Summary with exact uint64 count and non-finite values."), Type: dto.MetricType_SUMMARY.Enum(),
		Metric: []*dto.Metric{{Summary: &dto.Summary{
			SampleCount: proto.Uint64(math.MaxUint64), SampleSum: proto.Float64(math.NaN()),
			Quantile: []*dto.Quantile{{Quantile: proto.Float64(0.5), Value: proto.Float64(math.NaN())}},
		}}},
	})
	return climodel.MetricsSnapshot{CapturedAt: time.Now().UTC(), ProcessStartedAt: time.Now().Add(-time.Hour).UTC(), Families: families}
}

func TestWriteMetricsFormatsAndCompleteHistograms(t *testing.T) {
	snapshot := metricsFormatFixture(t)
	for _, selected := range []MetricsFormat{MetricsText, MetricsJson, MetricsOpenMetrics, MetricsWireCbor} {
		t.Run(string(selected), func(t *testing.T) {
			var output bytes.Buffer
			require.NoError(t, WriteMetrics(&output, selected, snapshot))
			switch selected {
			case MetricsText:
				require.Contains(t, output.String(), "Snapshot:")
				require.Contains(t, output.String(), "METRIC")
				for _, name := range []string{"test_duration_seconds_bucket", "test_duration_seconds_sum", "test_duration_seconds_count", `le="+Inf"`, "+Inf"} {
					require.Contains(t, output.String(), name)
				}
				require.NotContains(t, output.String(), "\x1b")
			case MetricsJson:
				var decoded struct {
					CapturedAt time.Time         `json:"capturedAt"`
					Families   []json.RawMessage `json:"families"`
				}
				require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
				require.Equal(t, snapshot.CapturedAt, decoded.CapturedAt)
				require.Len(t, decoded.Families, len(snapshot.Families))
				for i, data := range decoded.Families {
					var family dto.MetricFamily
					require.NoError(t, protojson.Unmarshal(data, &family))
					require.True(t, proto.Equal(snapshot.Families[i], &family))
				}
				require.Contains(t, output.String(), `"Infinity"`)
				require.Contains(t, output.String(), `"NaN"`)
				require.Contains(t, output.String(), `"18446744073709551615"`)
			case MetricsOpenMetrics:
				require.True(t, strings.HasSuffix(output.String(), "# EOF\n"))
				require.Equal(t, 1, strings.Count(output.String(), "# EOF\n"))
				require.Contains(t, output.String(), "# TYPE test_duration_seconds histogram\n")
				parser := expfmt.NewTextParser(model.LegacyValidation)
				families, err := parser.TextToMetricFamilies(bytes.NewReader(output.Bytes()))
				require.NoError(t, err)
				h := families["test_duration_seconds"]
				require.Len(t, h.Metric, 2)
				require.Equal(t, uint64(1), h.Metric[0].Histogram.GetSampleCount())
				require.Len(t, h.Metric[0].Histogram.Bucket, 3, "include the implicit +Inf bucket")
			case MetricsWireCbor:
				var decoded climodel.MetricsSnapshot
				require.NoError(t, transport.DecodeWireResult(bytes.NewReader(output.Bytes()), &decoded))
				require.Equal(t, snapshot.CapturedAt, decoded.CapturedAt)
				require.Equal(t, snapshot.ProcessStartedAt, decoded.ProcessStartedAt)
				for i, family := range snapshot.Families {
					require.True(t, proto.Equal(family, decoded.Families[i]), family.GetName())
				}
			}
		})
	}
}

func TestWriteMetricsEmptyUnsupportedAndOutputErrors(t *testing.T) {
	for _, selected := range []MetricsFormat{MetricsText, MetricsJson, MetricsOpenMetrics, MetricsWireCbor} {
		var output bytes.Buffer
		require.NoError(t, WriteMetrics(&output, selected, climodel.MetricsSnapshot{}))
		require.NotEmpty(t, output.Bytes())
		require.Error(t, WriteMetrics(metricsBrokenWriter{}, selected, metricsFormatFixture(t)))
	}
	for _, selected := range []MetricsFormat{"yaml", "cbor", "openmetric", "unknown"} {
		var output bytes.Buffer
		require.Error(t, WriteMetrics(&output, selected, climodel.MetricsSnapshot{}))
		require.Empty(t, output.Bytes())
	}
}

func TestWriteMetricsKeepsWireResponseBound(t *testing.T) {
	name, help := "test_large", strings.Repeat("x", transport.MaxWireResultBytes)
	snapshot := climodel.MetricsSnapshot{Families: []*dto.MetricFamily{{Name: &name, Help: &help, Type: dto.MetricType_GAUGE.Enum()}}}
	var output bytes.Buffer
	require.ErrorContains(t, WriteMetrics(&output, MetricsWireCbor, snapshot), "management response exceeds")
	require.Empty(t, output.Bytes())
}

func TestWriteMetricsRejectsMalformedWireSnapshotsBeforeOutput(t *testing.T) {
	for _, families := range [][]*dto.MetricFamily{
		{nil},
		{{Name: proto.String("invalid"), Type: dto.MetricType_GAUGE.Enum(), Metric: []*dto.Metric{nil}}},
		{{Name: proto.String("invalid"), Type: dto.MetricType_HISTOGRAM.Enum(), Metric: []*dto.Metric{{Histogram: &dto.Histogram{Bucket: []*dto.Bucket{nil}}}}}},
		{{Name: proto.String("invalid"), Type: dto.MetricType_COUNTER.Enum(), Metric: []*dto.Metric{{Counter: &dto.Counter{Exemplar: &dto.Exemplar{Label: []*dto.LabelPair{nil}}}}}}},
	} {
		// Include an otherwise valid prefix: validation must finish before even
		// the snapshot header or the first valid family is written.
		families = append(metricsFormatFixture(t).Families, families...)
		encoded, err := transport.EncodeWireResult(climodel.MetricsSnapshot{Families: families})
		require.NoError(t, err)
		var snapshot climodel.MetricsSnapshot
		require.NoError(t, transport.DecodeWireResult(bytes.NewReader(encoded), &snapshot))
		for _, selected := range []MetricsFormat{MetricsText, MetricsJson, MetricsOpenMetrics, MetricsWireCbor} {
			var output bytes.Buffer
			require.NotPanics(t, func() {
				require.ErrorContains(t, WriteMetrics(&output, selected, snapshot), "invalid metrics snapshot")
			})
			require.Empty(t, output.Bytes())
		}
	}
}

func FuzzMetricsWireSnapshotRendering(f *testing.F) {
	for _, snapshot := range []climodel.MetricsSnapshot{
		{},
		{Families: []*dto.MetricFamily{nil}},
		{Families: []*dto.MetricFamily{{Name: proto.String("test"), Type: dto.MetricType_GAUGE.Enum(), Metric: []*dto.Metric{nil}}}},
		{Families: []*dto.MetricFamily{{Name: proto.String("test"), Type: dto.MetricType_GAUGE.Enum(), Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: proto.Float64(1)}}}}}},
	} {
		encoded, err := transport.EncodeWireResult(snapshot)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 64<<10 {
			t.Skip()
		}
		var snapshot climodel.MetricsSnapshot
		if transport.DecodeWireResult(bytes.NewReader(encoded), &snapshot) != nil {
			return
		}
		for _, selected := range []MetricsFormat{MetricsText, MetricsJson, MetricsOpenMetrics} {
			_ = WriteMetrics(io.Discard, selected, snapshot)
		}
	})
}

type metricsBrokenWriter struct{}

func (metricsBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("output failed") }

var _ io.Writer = metricsBrokenWriter{}
