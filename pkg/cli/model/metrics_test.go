package model

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestMetricsSnapshotValidation(t *testing.T) {
	valid := func(kind dto.MetricType, metric *dto.Metric) MetricsSnapshot {
		return MetricsSnapshot{Families: []*dto.MetricFamily{{Name: proto.String("test_metric"), Type: kind.Enum(), Metric: []*dto.Metric{metric}}}}
	}
	for _, snapshot := range []MetricsSnapshot{
		{},
		valid(dto.MetricType_COUNTER, &dto.Metric{Counter: &dto.Counter{}}),
		valid(dto.MetricType_GAUGE, &dto.Metric{Gauge: &dto.Gauge{}}),
		valid(dto.MetricType_UNTYPED, &dto.Metric{Untyped: &dto.Untyped{}}),
		valid(dto.MetricType_SUMMARY, &dto.Metric{Summary: &dto.Summary{}}),
		valid(dto.MetricType_HISTOGRAM, &dto.Metric{Histogram: &dto.Histogram{}}),
		valid(dto.MetricType_GAUGE_HISTOGRAM, &dto.Metric{Histogram: &dto.Histogram{}}),
	} {
		require.NoError(t, snapshot.Validate())
	}
	for _, test := range []struct {
		name     string
		snapshot MetricsSnapshot
	}{
		{"nil-family", MetricsSnapshot{Families: []*dto.MetricFamily{nil}}},
		{"empty-family", MetricsSnapshot{Families: []*dto.MetricFamily{{}}}},
		{"missing-name", MetricsSnapshot{Families: []*dto.MetricFamily{{Type: dto.MetricType_GAUGE.Enum()}}}},
		{"missing-type", MetricsSnapshot{Families: []*dto.MetricFamily{{Name: proto.String("metric")}}}},
		{"unknown-type", valid(dto.MetricType(99), &dto.Metric{})},
		{"nil-metric", valid(dto.MetricType_GAUGE, nil)},
		{"missing-payload", valid(dto.MetricType_GAUGE, &dto.Metric{})},
		{"wrong-payload", valid(dto.MetricType_GAUGE, &dto.Metric{Counter: &dto.Counter{}})},
		{"ambiguous-payload", valid(dto.MetricType_GAUGE, &dto.Metric{Gauge: &dto.Gauge{}, Counter: &dto.Counter{}})},
		{"nil-label", valid(dto.MetricType_GAUGE, &dto.Metric{Gauge: &dto.Gauge{}, Label: []*dto.LabelPair{nil}})},
		{"unnamed-label", valid(dto.MetricType_GAUGE, &dto.Metric{Gauge: &dto.Gauge{}, Label: []*dto.LabelPair{{}}})},
		{"nil-quantile", valid(dto.MetricType_SUMMARY, &dto.Metric{Summary: &dto.Summary{Quantile: []*dto.Quantile{nil}}})},
		{"nil-bucket", valid(dto.MetricType_HISTOGRAM, &dto.Metric{Histogram: &dto.Histogram{Bucket: []*dto.Bucket{nil}}})},
		{"nil-exemplar-label", valid(dto.MetricType_COUNTER, &dto.Metric{Counter: &dto.Counter{Exemplar: &dto.Exemplar{Label: []*dto.LabelPair{nil}}}})},
		{"nil-bucket-exemplar-label", valid(dto.MetricType_HISTOGRAM, &dto.Metric{Histogram: &dto.Histogram{Bucket: []*dto.Bucket{{Exemplar: &dto.Exemplar{Label: []*dto.LabelPair{nil}}}}}})},
		{"nil-native-exemplar", valid(dto.MetricType_HISTOGRAM, &dto.Metric{Histogram: &dto.Histogram{Exemplars: []*dto.Exemplar{nil}}})},
		{"nil-native-exemplar-label", valid(dto.MetricType_HISTOGRAM, &dto.Metric{Histogram: &dto.Histogram{Exemplars: []*dto.Exemplar{{Label: []*dto.LabelPair{nil}}}}})},
		{"nil-negative-span", valid(dto.MetricType_HISTOGRAM, &dto.Metric{Histogram: &dto.Histogram{NegativeSpan: []*dto.BucketSpan{nil}}})},
		{"nil-positive-span", valid(dto.MetricType_HISTOGRAM, &dto.Metric{Histogram: &dto.Histogram{PositiveSpan: []*dto.BucketSpan{nil}}})},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorContains(t, test.snapshot.Validate(), "invalid metrics snapshot")
		})
	}
}
