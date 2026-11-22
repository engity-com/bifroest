package service

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/access"
)

var monitoringProcessStartedAt = time.Now().UTC()

type managementMetrics struct {
	service *service
	task environment.TaskContext
}

func (m managementMetrics) Snapshot(ctx context.Context, names []string) (model.MetricsSnapshot, error) {
	if err := m.service.requireManagement(ctx, m.task, access.MetricsRead); err != nil {
		return model.MetricsSnapshot{}, err
	}
	return m.service.monitoring.Snapshot(ctx, names)
}

// Remember sparse vector families at construction, without creating synthetic
// label sets just to make them appear in Gather. This catalog is immutable once
// the service is published.
func (m *serviceMonitoring) counterVec(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	m.knownFamilies[prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name)] = struct{}{}
	return prometheus.NewCounterVec(opts, labels)
}

func (m *serviceMonitoring) gaugeVec(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	m.knownFamilies[prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name)] = struct{}{}
	return prometheus.NewGaugeVec(opts, labels)
}

func (m *serviceMonitoring) histogramVec(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	m.knownFamilies[prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name)] = struct{}{}
	return prometheus.NewHistogramVec(opts, labels)
}

func (m *serviceMonitoring) setReady(ready bool) {
	m.ready.Store(ready)
	m.endpoint.SetReady(ready)
}

func (m *serviceMonitoring) Snapshot(ctx context.Context, names []string) (model.MetricsSnapshot, error) {
	result := model.MetricsSnapshot{}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if m == nil {
		return result, fmt.Errorf("management metrics are unavailable")
	}
	result.CapturedAt = time.Now().UTC()
	result.ProcessStartedAt = m.startedAt
	families, err := m.registry.Gather()
	if err != nil {
		return model.MetricsSnapshot{}, fmt.Errorf("cannot gather metrics: %w", err)
	}
	known := make(map[string]struct{}, len(m.knownFamilies)+len(families))
	for name := range m.knownFamilies {
		known[name] = struct{}{}
	}
	for _, family := range families {
		known[family.GetName()] = struct{}{}
	}
	selected := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, ok := known[name]; !ok {
			return model.MetricsSnapshot{}, fmt.Errorf("unknown metric family %q", name)
		}
		selected[name] = struct{}{}
	}
	result.Families = make([]*dto.MetricFamily, 0, len(families))
	for _, family := range families {
		if _, ok := selected[family.GetName()]; len(selected) == 0 || ok {
			result.Families = append(result.Families, family)
		}
	}
	if err := ctx.Err(); err != nil {
		return model.MetricsSnapshot{}, err
	}
	return result, nil
}
