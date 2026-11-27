package service

import "github.com/prometheus/client_golang/prometheus"

func (this *serviceMonitoring) collectTLS(ch chan<- prometheus.Metric, svc *service) {
	if svc.Service == nil {
		return
	}
	for _, source := range svc.tlsSourceNames {
		manager := svc.tlsManagers[source]
		if manager == nil {
			continue
		}
		for name, expires := range manager.Expirations() {
			ch <- prometheus.MustNewConstMetric(this.descriptions["tls_certificate_expiration_timestamp_seconds"],
				prometheus.GaugeValue, float64(expires.Unix()), source, name)
		}
	}
	consumers, err := activeTLSConsumers(&svc.Configuration)
	if err != nil {
		return
	}
	for _, consumer := range consumers {
		ready := false
		if binding := svc.tlsBindings[consumer.id]; binding != nil {
			ready = binding.Ready()
		} else if manager := svc.tlsManagers[consumer.source]; manager != nil {
			ready = manager.Ready()
		}
		ch <- prometheus.MustNewConstMetric(this.descriptions["tls_binding_ready"], prometheus.GaugeValue,
			monitoringBool(ready), consumer.source, consumer.id)
	}
}

func (this *service) httpTLSUses(source string) bool {
	h := this.Configuration.Http
	if !h.IsEnabled() || !h.Tls.IsEnabled() {
		return false
	}
	if h.Tls.Reference != "" {
		return source == "tls:"+h.Tls.Reference
	}
	return source == "http"
}
