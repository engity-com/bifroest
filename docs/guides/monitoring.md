---
description: Enable monitoring, scrape a Bifröst instance with Prometheus and configure Kubernetes probes.
---

# Monitor a Bifröst instance

This guide queries metrics from an installed, configured Bifröst instance through management SSH or an existing Prometheus installation. Prometheus scraping and Kubernetes probes do not require browser or management access. The [monitoring reference](../reference/monitoring.md) defines all settings and metric semantics.

## Examples

### Query metrics through management SSH

1. Set up the [management flow and workstation alias](management.md). No monitoring listener or Prometheus installation is needed for this example.
2. Query the running instance:

    ```shell
    bifroest @bifroest-admin metrics show bifroest_connections_active bifroest_sessions_active
    ```

    The default table shows current values and labels. For scripts or an OpenMetrics snapshot, use `--format=json` or `--format=openmetrics`. Omit metric names to show all available families. See [`metrics show`](../reference/cli/metrics/show.md) for filtering and output details.

### Scrape a host locally

1. Add the monitoring block to the existing Bifröst configuration:

    ```yaml title="Bifröst configuration"
    monitoring:
      enabled: true
      addresses: ["localhost:9090"]
    ```

    Restart Bifröst using the host's service manager. If Prometheus also listens on this host, configure a different port for one of the listeners.

2. Check readiness and metrics from the same host:

    ```shell title="Bifröst host"
    curl --fail http://localhost:9090/ready
    curl --fail http://localhost:9090/metrics
    ```

    `/ready` returns `ready` after startup. Metrics include `bifroest_ready 1`.

3. Add a scrape job to the local Prometheus configuration and reload Prometheus:

    ```yaml title="prometheus.yml"
    scrape_configs:
      - job_name: bifroest
        scrape_interval: 15s
        static_configs:
          - targets: ["localhost:9090"]
    ```

    In Prometheus, check `up{job="bifroest"}` and `bifroest_ready`. Both should be `1`. Scrape each instance separately; do not hide individual instances behind a load-balanced scrape target.

### Use a bearer token

1. Mount or provision the same secret token in separate private files readable by Bifröst and Prometheus. Add its path to Bifröst:

    ```yaml title="Bifröst configuration"
    monitoring:
      enabled: true
      bearerTokenFile: /run/secrets/monitoring-token
    ```

2. Configure Prometheus to send it:

    ```yaml title="Prometheus scrape job"
    job_name: bifroest
    authorization:
      credentials_file: /run/secrets/bifroest-monitoring-token
    static_configs:
      - targets: ["localhost:9090"]
    ```

    Restart Bifröst and reload Prometheus. `/metrics` now requires the token; the minimal `/ready` and `/status` probes remain token-free. For remote scraping, configure a private reachable address, an appropriate peer allowlist and [TLS](../reference/monitoring.md#tls) or an encrypted network. HTTP alone does not protect the token from interception.

### Configure Kubernetes probes

1. In the Bifröst Pod's existing configuration, bind monitoring to the Pod network:

    ```yaml title="Bifröst configuration"
    monitoring:
      enabled: true
      addresses: [":9090"]
      allowedRemoteHosts: []
    ```

    Restrict this port through your cluster networking policy and do not publish it externally. An empty allowlist permits every reachable peer. If you configure IP/CIDR entries, include the actual Prometheus and node/probe source ranges, not just the Pod network.

2. Add the named port and probes to the existing Bifröst container specification:

    ```yaml title="Bifröst container fragment"
    ports:
      - name: monitoring
        containerPort: 9090
    startupProbe:
      httpGet:
        path: /ready
        port: monitoring
      periodSeconds: 5
      timeoutSeconds: 2
      failureThreshold: 60
    readinessProbe:
      httpGet:
        path: /ready
        port: monitoring
      periodSeconds: 5
      timeoutSeconds: 2
    livenessProbe:
      httpGet:
        path: /status
        port: monitoring
      periodSeconds: 10
      timeoutSeconds: 2
    ```

    This allows roughly five minutes for startup before Kubernetes restarts the container. Adjust the budget to your deployment. Startup gates the other probes; readiness failures remove the Pod from normal Service traffic without themselves causing a restart. A slow IdP or failed remote delivery does not deliberately fail liveness. With monitoring TLS enabled, set `scheme: HTTPS` on each HTTP probe; Kubernetes HTTPS probes do not validate the server certificate.

3. Roll out the updated Pod specification and inspect its readiness with `kubectl get pods`. Configure your existing Prometheus discovery to scrape each Pod's `monitoring` port at `/metrics`, including bearer authorization if enabled.

### Add operational alerts

Add these example rules to your existing Prometheus rule group and adapt the thresholds:

```yaml title="Prometheus alert rules"
groups:
  - name: bifroest
    rules:
      - alert: BifroestMetricsUnavailable
        expr: up{job="bifroest"} == 0
        for: 2m
      - alert: BifroestAuditlogDisabled
        expr: bifroest_auditlog_disabled == 1
        for: 1m
      - alert: BifroestRecordingSpoolPressure
        expr: bifroest_recording_spool_bytes / bifroest_recording_spool_limit_bytes > 0.85
        for: 5m
      - alert: BifroestRecordingAccountingUnavailable
        expr: bifroest_recording_spool_accounting_valid == 0
        for: 2m
      - alert: BifroestDeliveryStalled
        expr: bifroest_remote_delivery_pending_observed_seconds > 300
        for: 2m
      - alert: BifroestCleanupFailing
        expr: bifroest_cleanup_problems > 0 or bifroest_cleanup_last_run_success{operation="housekeeping"} == 0
        for: 15m
      - alert: BifroestJournalSpaceLow
        expr: (bifroest_auditlog_available_bytes < bifroest_auditlog_minimum_free_bytes * 2) and on (job, instance, auditlog) (bifroest_auditlog_space_observation_valid == 1) and on (job, instance, auditlog) (time() - bifroest_auditlog_space_observation_timestamp_seconds < 60)
        for: 2m
      - alert: BifroestHttpCertificateExpiring
        expr: bifroest_http_tls_certificate_expiration_timestamp_seconds - time() < 7 * 86400
        for: 5m
      - alert: BifroestHttpServerErrors
        expr: sum by (job, instance) (rate(bifroest_http_requests_total{status=~"5.."}[5m])) / sum by (job, instance) (rate(bifroest_http_requests_total[5m])) > 0.05
        for: 5m
```

An unavailable scrape can mean a network, authorization or listener problem; it is not proof that workload access has failed. Resolve a disabled best-effort logger's cause and restart Bifröst to re-enable it. The delivery alert detects observed worker stalls, not a complete historical delivery backlog.

For access/security dashboards, use `sum by (transport, result) (rate(bifroest_authentication_attempts_total[5m]))`, `rate(bifroest_connections_rejected_total[5m])` and `rate(bifroest_http_rejections_total[5m])`. `increase(...[1h])` gives the corresponding hourly event count. Investigate sustained changes together with unauthenticated SSH connections, TLS aborts and audit-detail suppression; do not treat every `401`/`403` or unauthenticated HTTP asset fetch as a failed login.

The weighted active-session average is `sum(bifroest_sessions_age_sum_seconds) / sum(bifroest_sessions_age_observations)` when the denominator is greater than zero. Use oldest age to find outliers, but not as an inactivity timeout. Successful streaming channel lifetimes are deliberately absent from normal HTTP latency histograms.

## Next steps

* [Monitoring reference](../reference/monitoring.md) defines labels, measurement boundaries and TLS configuration.
* [Audit logs](../reference/auditlog/index.md) explains strict and best-effort failure policies.
* [Housekeeping](../reference/housekeeping.md) describes retained sessions and conservative cleanup.
