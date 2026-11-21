package service

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type monitoringJournal struct{ available, valid, observed *prometheus.GaugeVec }

func (m *serviceMonitoring) initJournal() {
	m.journal.available = m.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_auditlog_available_bytes", Help: "Last successfully observed bytes available on the actual journal filesystem; consult observation validity and timestamp."}, []string{"auditlog"})
	m.journal.valid = m.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_auditlog_space_observation_valid", Help: "Whether the most recent background journal-space observation succeeded."}, []string{"auditlog"})
	m.journal.observed = m.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_auditlog_space_observation_timestamp_seconds", Help: "Timestamp of the latest successful journal-space observation."}, []string{"auditlog"})
	m.registry.MustRegister(m.journal.available, m.journal.valid, m.journal.observed)
}

type monitoringJournalResult struct {
	name      configuration.AuditlogName
	available uint64
	err       error
}

func (m *serviceMonitoring) runJournalObserver(ctx context.Context, svc *service) error {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	return m.observeJournalSpace(ctx, svc, ticker.C)
}

func (m *serviceMonitoring) observeJournalSpace(ctx context.Context, svc *service, ticks <-chan time.Time) error {
	observers := make(map[configuration.AuditlogName]audit.JournalSpaceObserver)
	for name, recorder := range svc.auditRecorders {
		wrapper, ok := recorder.(*failurePolicyAuditRecorder)
		if !ok {
			continue
		}
		observer, ok := wrapper.delegate.(audit.JournalSpaceObserver)
		if !ok {
			continue
		}
		observers[name] = observer
	}
	// A filesystem syscall may not be cancelable. Keep at most one outstanding
	// call per journal, and never make it part of the listener's shutdown drain.
	// Workers own no service state and publish only through this bounded channel.
	results := make(chan monitoringJournalResult, len(observers))
	pending := make(map[configuration.AuditlogName]bool, len(observers))
	defer func() {
		for name := range observers {
			m.journal.valid.WithLabelValues(name.String()).Set(0)
		}
	}()
	sample := func() {
		for name, observer := range observers {
			if ctx.Err() != nil {
				return
			}
			if pending[name] {
				// A query still pending at the next sampling interval is stale.
				m.journal.valid.WithLabelValues(name.String()).Set(0)
				continue
			}
			pending[name] = true
			go func() {
				if ctx.Err() != nil {
					return
				}
				available, err := observer.JournalAvailableBytes()
				select {
				case results <- monitoringJournalResult{name, available, err}:
				case <-ctx.Done():
				}
			}()
		}
	}
	sample()
	for {
		select {
		case <-ctx.Done():
			return nil
		case result := <-results:
			if ctx.Err() != nil {
				return nil
			}
			delete(pending, result.name)
			name := result.name.String()
			m.journal.valid.WithLabelValues(name).Set(monitoringBool(result.err == nil))
			if result.err == nil {
				m.journal.available.WithLabelValues(name).Set(float64(result.available))
				m.journal.observed.WithLabelValues(name).SetToCurrentTime()
			}
		case <-ticks:
			sample()
		}
	}
}
