package model

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	dto "github.com/prometheus/client_model/go"
)

// MetricsSnapshot contains the same complete families as the monitoring scrape.
// Timestamps describe the observation, not a history or an atomic transaction.
type MetricsSnapshot struct {
	CapturedAt       time.Time           `json:"capturedAt"`
	ProcessStartedAt time.Time           `json:"processStartedAt"`
	Families         []*dto.MetricFamily `json:"families"`
}

// Validate checks the structural invariants required by metric renderers before
// any output is published. Valid non-finite sample values remain supported.
func (this MetricsSnapshot) Validate() error {
	for i, family := range this.Families {
		if family == nil || family.GetName() == "" || family.Type == nil {
			return fmt.Errorf("invalid metrics snapshot: family %d has no name or type", i)
		}
		switch family.GetType() {
		case dto.MetricType_COUNTER, dto.MetricType_GAUGE, dto.MetricType_SUMMARY, dto.MetricType_UNTYPED, dto.MetricType_HISTOGRAM, dto.MetricType_GAUGE_HISTOGRAM:
		default:
			return fmt.Errorf("invalid metrics snapshot: family %d has an unknown type", i)
		}
		for j, metric := range family.Metric {
			if err := validateSnapshotMetric(family.GetType(), metric); err != nil {
				return fmt.Errorf("invalid metrics snapshot: family %d metric %d: %w", i, j, err)
			}
		}
	}
	return nil
}

func validateSnapshotMetric(kind dto.MetricType, metric *dto.Metric) error {
	if metric == nil {
		return fmt.Errorf("missing metric")
	}
	if err := validateSnapshotLabels(metric.Label); err != nil {
		return err
	}
	payloads := 0
	matched := false
	if metric.Counter != nil {
		payloads++
		matched = kind == dto.MetricType_COUNTER
		if err := validateSnapshotExemplar(metric.Counter.Exemplar); err != nil {
			return err
		}
	}
	if metric.Gauge != nil {
		payloads++
		matched = kind == dto.MetricType_GAUGE
	}
	if metric.Untyped != nil {
		payloads++
		matched = kind == dto.MetricType_UNTYPED
	}
	if metric.Summary != nil {
		payloads++
		matched = kind == dto.MetricType_SUMMARY
		for _, quantile := range metric.Summary.Quantile {
			if quantile == nil {
				return fmt.Errorf("missing summary quantile")
			}
		}
	}
	if metric.Histogram != nil {
		payloads++
		matched = kind == dto.MetricType_HISTOGRAM || kind == dto.MetricType_GAUGE_HISTOGRAM
		for _, bucket := range metric.Histogram.Bucket {
			if bucket == nil {
				return fmt.Errorf("missing histogram bucket")
			}
			if err := validateSnapshotExemplar(bucket.Exemplar); err != nil {
				return err
			}
		}
		for _, exemplar := range metric.Histogram.Exemplars {
			if exemplar == nil {
				return fmt.Errorf("missing histogram exemplar")
			}
			if err := validateSnapshotExemplar(exemplar); err != nil {
				return err
			}
		}
		for _, spans := range [][]*dto.BucketSpan{metric.Histogram.NegativeSpan, metric.Histogram.PositiveSpan} {
			for _, span := range spans {
				if span == nil {
					return fmt.Errorf("missing histogram span")
				}
			}
		}
	}
	if payloads != 1 || !matched {
		return fmt.Errorf("metric payload does not match its family type")
	}
	return nil
}

func validateSnapshotLabels(labels []*dto.LabelPair) error {
	for _, label := range labels {
		if label == nil || label.GetName() == "" {
			return fmt.Errorf("missing metric label name")
		}
	}
	return nil
}

func validateSnapshotExemplar(exemplar *dto.Exemplar) error {
	if exemplar == nil {
		return nil
	}
	return validateSnapshotLabels(exemplar.Label)
}

// MarshalCBOR keeps the observation's fractional timestamp across the SSH transport
// instead of CBOR's default whole-second time representation.
func (this MetricsSnapshot) MarshalCBOR() ([]byte, error) {
	mode, err := (cbor.EncOptions{Time: cbor.TimeRFC3339Nano}).EncMode()
	if err != nil {
		return nil, err
	}
	type plain MetricsSnapshot
	return mode.Marshal(plain(this))
}
