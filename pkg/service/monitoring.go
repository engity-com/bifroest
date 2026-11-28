package service

import (
	"slices"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/monitoring"
)

var monitoringFlowLabels = []string{"flow", "authorization", "auditlog", "environment"}

type serviceMonitoring struct {
	*serviceMonitoringState
	flows map[configuration.FlowName][]string
}

// Metrics, endpoints, budgets and locks belong to the process. Each generation
// has a small immutable label view so retained work keeps its original labels.
type serviceMonitoringState struct {
	endpoint           *monitoring.Endpoint
	registry           *prometheus.Registry
	knownFamilies      map[string]struct{}
	startedAt          time.Time
	ready              atomic.Bool
	service            atomic.Pointer[service]
	configuration      configuration.Configuration
	evaluations        *prometheus.CounterVec
	durations          *prometheus.HistogramVec
	completions        *prometheus.CounterVec
	auditErrors        *prometheus.CounterVec
	recordingErrors    *prometheus.CounterVec
	cleanupRuns        *prometheus.CounterVec
	cleanupSuccess     *prometheus.GaugeVec
	cleanupLastSuccess *prometheus.GaugeVec
	cleanupProblems    *prometheus.GaugeVec
	cleanupScanTime    *prometheus.GaugeVec
	tasks              *prometheus.GaugeVec
	tlsRenewalErrors   *prometheus.CounterVec
	descriptions       map[string]*prometheus.Desc
	access             monitoringAccess
	http               monitoringHTTP
	journal            monitoringJournal
	reload             monitoringReload
}

func newServiceMonitoring(conf configuration.Configuration, force ...bool) (*serviceMonitoring, error) {
	management := false
	for _, flow := range conf.Flows {
		if _, ok := flow.Environment.V.(*configuration.EnvironmentManagement); ok {
			management = true
			break
		}
	}
	collect := conf.Monitoring.IsEnabled() || management || len(force) > 0 && force[0]
	if !collect {
		return nil, nil
	}
	result := (&serviceMonitoring{serviceMonitoringState: &serviceMonitoringState{registry: prometheus.NewRegistry(), knownFamilies: make(map[string]struct{}), startedAt: monitoringProcessStartedAt, configuration: conf, descriptions: make(map[string]*prometheus.Desc)}}).view(conf)
	authLabels := append(append([]string{}, monitoringFlowLabels...), "transport", "method", "phase", "result", "error_category")
	result.evaluations = result.counterVec(prometheus.CounterOpts{Name: "bifroest_authentication_flow_evaluations_total", Help: "Provider evaluations, not completed authentications."}, authLabels)
	result.durations = result.histogramVec(prometheus.HistogramOpts{Name: "bifroest_authentication_flow_evaluation_duration_seconds", Help: "Provider evaluation time, excluding audit/observer work; interactive methods include user waiting.", Buckets: []float64{.005, .025, .1, .5, 1, 5, 15, 60, 300}}, authLabels)
	result.completions = result.counterVec(prometheus.CounterOpts{Name: "bifroest_authentication_completions_total", Help: "Explicit authentication completion decisions, not transport or browser credential publication."}, append(append([]string{}, monitoringFlowLabels...), "transport", "method", "result", "error_category"))
	result.auditErrors = result.counterVec(prometheus.CounterOpts{Name: "bifroest_auditlog_errors_total", Help: "Auditlog failures reported to the failure policy."}, []string{"auditlog", "error_category"})
	result.recordingErrors = result.counterVec(prometheus.CounterOpts{Name: "bifroest_recording_errors_total", Help: "Recording failures reported to the failure policy."}, []string{"auditlog", "error_category"})
	cleanupLabels := append(append([]string{}, monitoringFlowLabels...), "operation")
	result.cleanupRuns = result.counterVec(prometheus.CounterOpts{Name: "bifroest_cleanup_runs_total", Help: "Cleanup operations, including failures handled without terminating housekeeping."}, append(cleanupLabels, "result"))
	result.cleanupSuccess = result.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_cleanup_last_run_success", Help: "Whether the last observed cleanup operation succeeded."}, cleanupLabels)
	result.cleanupLastSuccess = result.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_cleanup_last_success_timestamp_seconds", Help: "Time of the last successful cleanup operation since process start."}, cleanupLabels)
	result.cleanupProblems = result.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_cleanup_problems", Help: "Unresolved session inspection/cleanup problems observed during the last housekeeping scan."}, monitoringFlowLabels)
	result.cleanupScanTime = result.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_cleanup_last_scan_timestamp_seconds", Help: "Time of the last completed housekeeping observation, including failed scans."}, nil)
	result.tasks = result.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_tasks_active", Help: "Running shell, command and subsystem tasks, not Bifroest sessions or idle channels."}, monitoringFlowLabels)
	for _, labels := range result.flows {
		result.tasks.WithLabelValues(labels...).Set(0)
	}
	result.registry.MustRegister(result.evaluations, result.durations, result.completions, result.auditErrors, result.recordingErrors, result.cleanupRuns, result.cleanupSuccess, result.cleanupLastSuccess, result.cleanupProblems, result.cleanupScanTime, result.tasks)
	result.registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	result.initAccess()
	result.initHTTP()
	result.tlsRenewalErrors = result.counterVec(prometheus.CounterOpts{Name: "bifroest_tls_renewal_errors_total", Help: "Failed certificate refresh rounds, once per active TLS source."}, []string{"source"})
	result.registry.MustRegister(result.tlsRenewalErrors)
	result.descriptions["tls_certificate_expiration_timestamp_seconds"] = prometheus.NewDesc("bifroest_tls_certificate_expiration_timestamp_seconds", "Effective certificate chain expiry per TLS source and registered name.", []string{"source", "name"}, nil)
	result.descriptions["tls_binding_ready"] = prometheus.NewDesc("bifroest_tls_binding_ready", "Whether a configured TLS consumer has valid material.", []string{"source", "consumer"}, nil)
	result.initJournal()
	result.initReload()
	for name, help := range map[string]string{
		"ready":              "Whether all configured access listeners have completed startup and are accepting new access.",
		"connections_active": "Open SSH transport connections, including unauthenticated connections and SSH tunnels.",
	} {
		result.descriptions[name] = prometheus.NewDesc("bifroest_"+name, help, nil, nil)
	}
	for name, help := range map[string]string{"sessions_active": "Distinct Bifroest sessions with registered live connections.", "session_connections_active": "Registered authenticated SSH/browser terminal connections."} {
		result.descriptions[name] = prometheus.NewDesc("bifroest_"+name, help, monitoringFlowLabels, nil)
	}
	for name, help := range map[string]string{
		"auditlog_enabled":                 "Whether this configured auditlog has not been disabled after a best-effort failure.",
		"auditlog_disabled":                "Whether this configured auditlog was disabled after a best-effort failure.",
		"recording_configured":             "Whether recording is configured for this auditlog.",
		"recording_spool_bytes":            "Accounted recording spool bytes including outstanding reservations.",
		"recording_spool_limit_bytes":      "Configured maximum accounted recording spool bytes.",
		"recording_spool_accounting_valid": "Whether in-memory recording spool accounting is available and trustworthy.",
		"auditlog_minimum_free_bytes":      "Configured minimum journal filesystem free-space reserve.",
	} {
		result.descriptions[name] = prometheus.NewDesc("bifroest_"+name, help, []string{"auditlog"}, nil)
	}
	for name, help := range map[string]string{
		"remote_delivery_errors_total":             "Worker retry failures since process start, including local state failures.",
		"remote_delivery_worker_pending":           "Whether the sequential worker has an observed outstanding delivery (0 or 1), not a complete backlog count.",
		"remote_delivery_pending_observed_seconds": "Seconds since the worker first observed its current outstanding delivery; not artifact creation age.",
	} {
		result.descriptions[name] = prometheus.NewDesc("bifroest_"+name, help, []string{"auditlog", "target", "kind"}, nil)
	}
	var err error
	result.endpoint, err = monitoring.New(conf.Monitoring, result.registry, monitoring.Options{DeferTLS: true})
	if err != nil {
		return nil, err
	}
	result.registry.MustRegister(result)
	for name := range result.descriptions {
		result.knownFamilies["bifroest_"+name] = struct{}{}
	}
	// Remember the runtime/process families available on this platform, too, so
	// a temporarily missing observation is not mistaken for an unknown name.
	// Observation failures must not add a new service-startup dependency.
	if families, err := result.registry.Gather(); err == nil {
		for _, family := range families {
			result.knownFamilies[family.GetName()] = struct{}{}
			if family.GetName() == "process_start_time_seconds" && len(family.Metric) == 1 {
				seconds := family.Metric[0].GetGauge().GetValue()
				result.startedAt = time.Unix(0, int64(seconds*1e9)).UTC()
			}
		}
	}
	return result, nil
}

func (this *serviceMonitoring) view(conf configuration.Configuration) *serviceMonitoring {
	if this == nil {
		return nil
	}
	result := &serviceMonitoring{serviceMonitoringState: this.serviceMonitoringState, flows: make(map[configuration.FlowName][]string, len(conf.Flows))}
	for _, flow := range conf.Flows {
		result.flows[flow.Name] = []string{flow.Name.String(), flow.Authorization.Reference, flow.Auditlog.String(), flow.Environment.Reference}
	}
	return result
}

func (this *serviceMonitoring) flowLabels(flow configuration.FlowName) []string {
	if labels, ok := this.flows[flow]; ok {
		return labels
	}
	return []string{"", "", "", ""}
}

func (this *serviceMonitoring) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range this.descriptions {
		ch <- desc
	}
}
func (this *serviceMonitoring) Collect(ch chan<- prometheus.Metric) {
	emit := func(name string, value float64, labels ...string) {
		kind := prometheus.GaugeValue
		if name == "remote_delivery_errors_total" {
			kind = prometheus.CounterValue
		}
		ch <- prometheus.MustNewConstMetric(this.descriptions[name], kind, value, labels...)
	}
	ready := this.ready.Load()
	if this.endpoint != nil {
		ready = this.endpoint.Ready()
	}
	emit("ready", monitoringBool(ready))
	svc := this.service.Load()
	if svc == nil {
		return
	}
	if svc.monitoring != nil {
		this = svc.monitoring
	}
	emit("connections_active", float64(svc.connectionCounter().Load()))
	this.collectAccess(ch, svc)
	this.collectHTTP(ch, svc)
	this.collectTLS(ch, svc)
	counts := svc.sessionConnections.monitoringCounts()
	for flow, labels := range this.flows {
		emit("sessions_active", float64(counts[flow][0]), labels...)
		emit("session_connections_active", float64(counts[flow][1]), labels...)
	}
	for _, logger := range this.configuration.Auditlogs {
		name := logger.Name.String()
		disabled := svc.auditlogDisabled(logger.Name)
		emit("auditlog_enabled", monitoringBool(!disabled), name)
		emit("auditlog_disabled", monitoringBool(disabled), name)
		emit("recording_configured", monitoringBool(logger.Recording.Enabled), name)
		emit("auditlog_minimum_free_bytes", float64(logger.MinimumFreeBytes), name)
		if logger.Recording.Enabled {
			emit("recording_spool_limit_bytes", float64(logger.Recording.MaximumSpoolBytes), name)
			valid := false
			if repository := svc.recordingRepositories[logger.Name]; repository != nil && repository.native != nil {
				usage, ok := repository.native.SpoolUsage()
				valid = ok
				if valid {
					emit("recording_spool_bytes", float64(usage), name)
				}
			}
			emit("recording_spool_accounting_valid", monitoringBool(valid), name)
		}
		collectDelivery := func(kind string, snapshots []audit.DeliverySnapshot) {
			for _, snapshot := range snapshots {
				labels := []string{name, snapshot.Target.String(), kind}
				emit("remote_delivery_errors_total", float64(snapshot.Errors), labels...)
				emit("remote_delivery_worker_pending", monitoringBool(!snapshot.PendingSince.IsZero()), labels...)
				age := 0.0
				if !snapshot.PendingSince.IsZero() {
					age = max(0, time.Since(snapshot.PendingSince).Seconds())
				}
				emit("remote_delivery_pending_observed_seconds", age, labels...)
			}
		}
		if delivery := svc.auditDeliveries[logger.Name]; delivery != nil {
			collectDelivery("audit", delivery.MonitoringSnapshots())
		}
		if delivery := svc.recordingDeliveries[logger.Name]; delivery != nil {
			collectDelivery("recording", delivery.MonitoringSnapshots())
		}
	}
}

func monitoringBool(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func (this *serviceMonitoring) observeFlow(observation authorization.FlowAuthorizationObservation) {
	if this == nil {
		return
	}
	labels := append(append([]string{}, this.flowLabels(observation.Flow)...), monitoringValue(string(observation.Transport), "ssh", "http"), monitoringValue(string(observation.Method), "public-key", "password", "keyboard-interactive", "browser-remember-me"), monitoringValue(string(observation.Phase), "", "candidate", "verified"), monitoringValue(string(observation.Outcome), "accepted", "denied", "failed"), string(auditErrorCategory(observation.Err)))
	this.evaluations.WithLabelValues(labels...).Inc()
	this.durations.WithLabelValues(labels...).Observe(max(0, observation.Duration.Seconds()))
}

func (this *serviceMonitoring) observeCompletion(flow configuration.FlowName, method audit.AuthenticationMethod, outcome audit.EventOutcome, err error, transports ...bconn.Transport) {
	if this == nil {
		return
	}
	if err != nil {
		outcome = audit.EventOutcomeFailure
	}
	transport := "unknown"
	if len(transports) > 0 {
		transport = monitoringValue(string(transports[0]), "ssh", "http")
	}
	labels := append(append([]string{}, this.flowLabels(flow)...), transport, monitoringValue(string(method), "public-key", "password", "keyboard-interactive", "browser-remember-me"), monitoringValue(string(outcome), "success", "denied", "failure"), string(auditErrorCategory(err)))
	this.completions.WithLabelValues(labels...).Inc()
}

func (this *serviceMonitoring) cleanup(flow configuration.FlowName, operation string, err error) {
	if this == nil {
		return
	}
	this.cleanupLabels(this.flowLabels(flow), operation, err)
}

func (this *serviceMonitoring) cleanupLabels(flowLabels []string, operation string, err error) {
	labels := append(append([]string{}, flowLabels...), operation)
	result := "success"
	if err != nil {
		result = "failure"
	}
	this.cleanupRuns.WithLabelValues(append(labels, result)...).Inc()
	this.cleanupSuccess.WithLabelValues(labels...).Set(monitoringBool(err == nil))
	if err == nil {
		this.cleanupLastSuccess.WithLabelValues(labels...).SetToCurrentTime()
	}
}

func (this *serviceMonitoring) cleanupSnapshot(problems map[configuration.FlowName]int) {
	if this == nil {
		return
	}
	if svc := this.service.Load(); svc != nil && svc.monitoring != nil {
		this = svc.monitoring
	}
	for flow, labels := range this.flows {
		this.cleanupProblems.WithLabelValues(labels...).Set(float64(problems[flow]))
	}
	this.cleanupProblems.WithLabelValues(this.flowLabels("")...).Set(float64(problems[""]))
	this.cleanupScanTime.WithLabelValues().SetToCurrentTime()
}

func monitoringValue(value string, allowed ...string) string {
	if slices.Contains(allowed, value) {
		return value
	}
	return "unknown"
}

func (this *serviceMonitoring) taskStarted(flow configuration.FlowName) func() {
	if this == nil {
		return func() {}
	}
	gauge := this.tasks.WithLabelValues(this.flowLabels(flow)...)
	gauge.Inc()
	return gauge.Dec
}
