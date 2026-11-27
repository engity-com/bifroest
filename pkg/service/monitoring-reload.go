package service

import "github.com/prometheus/client_golang/prometheus"

type monitoringReload struct {
	enabled      prometheus.Gauge
	attempts     *prometheus.CounterVec
	watchErrors  prometheus.Counter
	lastSuccess  prometheus.Gauge
	lastAttempt  prometheus.Gauge
	lastAccepted prometheus.Gauge
}

func (this *serviceMonitoring) initReload() {
	this.reload = monitoringReload{
		enabled:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "bifroest_configuration_watch_enabled", Help: "Whether configuration file watching was explicitly requested."}),
		attempts:     this.counterVec(prometheus.CounterOpts{Name: "bifroest_configuration_reload_attempts_total", Help: "Configuration reread results, including unchanged polling attempts."}, []string{"result"}),
		watchErrors:  prometheus.NewCounter(prometheus.CounterOpts{Name: "bifroest_configuration_watch_errors_total", Help: "Native file watch degradation reports; polling continues."}),
		lastSuccess:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "bifroest_configuration_reload_last_success", Help: "Whether the last completed configuration reread was accepted."}),
		lastAttempt:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "bifroest_configuration_reload_last_attempt_timestamp_seconds", Help: "Time of the last completed configuration reread; zero before the first attempt."}),
		lastAccepted: prometheus.NewGauge(prometheus.GaugeOpts{Name: "bifroest_configuration_reload_last_accepted_timestamp_seconds", Help: "Time of the last accepted configuration reread, including unchanged input."}),
	}
	this.registry.MustRegister(this.reload.enabled, this.reload.attempts, this.reload.watchErrors, this.reload.lastSuccess, this.reload.lastAttempt, this.reload.lastAccepted)
}

func (this *serviceMonitoring) observeReload(result string) {
	this.reload.attempts.WithLabelValues(result).Inc()
	this.reload.lastSuccess.Set(monitoringBool(result != "rejected"))
	this.reload.lastAttempt.SetToCurrentTime()
	if result != "rejected" {
		this.reload.lastAccepted.SetToCurrentTime()
	}
}
