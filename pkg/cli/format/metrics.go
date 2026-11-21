package format

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/prometheus/common/expfmt"
	pmodel "github.com/prometheus/common/model"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/engity-com/bifroest/pkg/cli/model"
)

func WriteMetrics(output io.Writer, selected MetricsFormat, snapshot model.MetricsSnapshot) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}
	switch selected {
	case MetricsWireCbor:
		return writeStructured(output, WireCbor, snapshot)
	case MetricsJson:
		// Protobuf JSON preserves uint64 counters and represents non-finite values
		// as strings, instead of failing on a valid NaN/Inf Prometheus sample.
		families := make([]json.RawMessage, 0, len(snapshot.Families))
		for _, family := range snapshot.Families {
			data, err := protojson.Marshal(family)
			if err != nil {
				return err
			}
			families = append(families, data)
		}
		return writeStructured(output, Json, struct {
			CapturedAt       time.Time         `json:"capturedAt"`
			ProcessStartedAt time.Time         `json:"processStartedAt"`
			Families         []json.RawMessage `json:"families"`
		}{snapshot.CapturedAt, snapshot.ProcessStartedAt, families})
	case MetricsOpenMetrics:
		if _, err := fmt.Fprintf(output, "# Snapshot captured_at=%s process_started_at=%s\n", snapshot.CapturedAt.Format(time.RFC3339Nano), snapshot.ProcessStartedAt.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		for _, family := range snapshot.Families {
			if _, err := expfmt.MetricFamilyToOpenMetrics(output, family); err != nil {
				return err
			}
		}
		_, err := expfmt.FinalizeOpenMetrics(output)
		return err
	case MetricsText:
		samples, err := expfmt.ExtractSamples(&expfmt.DecodeOptions{}, snapshot.Families...)
		if err != nil {
			return err
		}
		rows := make([][]string, 0, len(samples))
		for _, sample := range samples {
			name := string(sample.Metric[pmodel.MetricNameLabel])
			delete(sample.Metric, pmodel.MetricNameLabel)
			rows = append(rows, []string{name, sample.Value.String(), sample.Metric.String()})
		}
		if _, err := fmt.Fprintf(output, "Snapshot: %s\nProcess started: %s\n", snapshot.CapturedAt.Format(time.RFC3339Nano), snapshot.ProcessStartedAt.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		return WriteList(output, Text, []string{"METRIC", "VALUE", "LABELS"}, rows, nil)
	default:
		return fmt.Errorf("unsupported metrics format %q", selected)
	}
}
