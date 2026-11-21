---
description: Configure a separate monitoring listener for Prometheus metrics and Kubernetes probes.
---

# Monitoring

The optional root `monitoring` block provides a separate operational listener. It does not require [HTTP browser access](connection/http/index.md), a management flow or an interactive login. See [Monitor a Bifröst instance](../guides/monitoring.md) for Prometheus and Kubernetes examples.

Metric collection is active when monitoring is enabled or at least one [management flow](environment/management.md) is configured. [`metrics show`](cli/metrics/show.md) queries the same measurements over management SSH, without opening a monitoring port or requiring a monitoring bearer token. Only `monitoring.enabled` starts the HTTP monitoring listener.

## Properties

<<property("enabled", "bool", default=False)>>
Starts the monitoring listener. When disabled or omitted, no monitoring listener starts and no monitoring token or certificate files are read.

<<property("addresses", array_ref("Net Address", "data-type.md#net-address"), default=["localhost:9090"])>>
Addresses to listen on. At least one is required when enabled. The default is loopback-only; Kubernetes HTTP probes need an explicitly configured address reachable through the Pod IP. Port `9090` is configurable and must not conflict with Prometheus or another local listener.

!!! warning
    Metrics include configured flow, authorization, environment, audit-log and remote-target names, and HTTP certificate domains. Keep the listener on a private network, restrict its peers, and do not expose it through a public Ingress or LoadBalancer. A bearer token does not encrypt HTTP traffic; use TLS or another encrypted transport outside a trusted network.

<<property("allowedRemoteHosts", array_ref("IP Address or Network", "data-type.md#ip-address-or-network"), default=[])>>
Allowed peers. An omitted, `null` or empty value allows every peer that can reach the listener. With entries, a peer must match at least one. Empty entries are ignored.

The filter applies to all endpoints and uses the direct connection's peer address, not `Forwarded` or `X-Forwarded-For`. Include the actual node/probe and scraper source ranges in Kubernetes. A proxy is itself the peer.

<<property("bearerToken", "string", default="")>>
Optional RFC 6750 bearer token protecting only `/metrics`. Cannot be combined with `bearerTokenFile`. `/ready` and `/status` remain token-free but are still subject to the peer filter.

<<property("bearerTokenFile", "File Path", "data-type.md#file-path", default="")>>
Reads the metrics bearer token from a local file at startup, suitable for a mounted Kubernetes Secret. The token may contain at most 4096 bytes, excluding a trailing line ending. Empty or invalid files prevent startup. Restart Bifröst after rotating the token.

<<property("tls", "TLS", "#tls")>>
Optional TLS using supplied certificate/key pairs. Without TLS, the listener serves HTTP.

<<property("readHeaderTimeout", "Duration", "data-type.md#duration", default="10s")>>
Request-header and request-read timeout. Must be positive.

<<property("idleTimeout", "Duration", "data-type.md#duration", default="1m")>>
Idle HTTP keep-alive timeout. Must be positive.

<<property("gracefulShutdownTimeout", "Duration", "data-type.md#duration", default="30s")>>
Maximum time for monitoring requests to finish on shutdown. `0s` closes them immediately.

<<property("maxHeaderBytes", "uint32", default=1048576)>>
Maximum request-header size, from `1` to `16777216` bytes.


## TLS

These properties belong to `monitoring.tls`.

<<property("enabled", "bool", default=False, id_prefix="tls-", heading=3)>>
Enables TLS. Requires at least one supplied certificate/key pair. No ACME, automatic issuance or generated fallback certificates are supported.

<<property("certificates", array_ref("Certificate", "#certificate"), id_prefix="tls-", heading=3)>>
PEM certificate/key pairs, using the same file-property names as [HTTP certificates](connection/http/index.md#certificate). Certificates are read at startup; restart Bifröst after replacing them.

### Certificate

Each entry in `monitoring.tls.certificates` has these properties.

<<property("certificateFile", "File Path", "data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
Local PEM certificate-chain file. Use a certificate trusted by your scraper and covering its connection name or IP.

<<property("privateKeyFile", "File Path", "data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
Matching protected PEM private-key file, owned by the Bifröst service account. Its key must be distinct from SSH, audit-signing, SFTP and audit-encryption keys. Certificate and key validation use the same requirements as HTTP TLS. For Kubernetes on Linux, mount the TLS key with owner-only permissions, such as `defaultMode: 0400`, and ownership that lets the service account read it.

```yaml title="Example"
monitoring:
  enabled: true
  addresses: ["192.0.2.10:9090"]
  allowedRemoteHosts: ["192.0.2.20"]
  bearerTokenFile: /run/secrets/monitoring-token
  tls:
    enabled: true
    certificates:
      - certificateFile: /etc/engity/bifroest/monitoring.crt
        privateKeyFile: /etc/engity/bifroest/monitoring.key
```

## Endpoints

All endpoints accept `GET` and `HEAD`. They do not perform test logins or target/backend health checks.

| Path | Purpose | Response |
| - | - | -  |
| `/status` | Minimal process liveness. External dependency failures do not make it fail. | `200`: `ok` |
| `/ready` | New-access readiness; usable for startup and readiness probes. | `200`: `ready`<br>`503`: `not ready` |
| `/metrics` | Operational metrics; requires the configured bearer token, if any. | `200`: [Metrics](#metrics) in [OpenMetrics Format](https://openmetrics.io/) |

## Metrics

Application metric names start with `bifroest_`. Counters and histogram observations start again with each process; gauges describe current or explicitly observed state. An event series appears after its first observation. Standard `go_*` and, where supported, `process_*` metrics are also provided.

Flow-related metrics use `flow`, `authorization`, `auditlog` and `environment`. The latter three are configured definition names, or empty for an unnamed inline/absent definition. Audit-log metrics use `auditlog`; delivery metrics additionally use configured `target` and `kind` (`audit` or `recording`). Shared components are counted once, not once per referring flow. No username, principal, session/Recording ID, target address, error text, claim or session content is a label.

| Metric | Type | Meaning |
| - | - | - |
| `bifroest_ready` | Gauge | `1` when ready for new access, otherwise `0`. |
| `bifroest_connections_active` | Gauge | Open SSH transport connections, including authentication attempts, direct SSH and SSH tunnels. Excludes monitoring and browser HTTP requests. |
| `bifroest_connections_unauthenticated` | Gauge | Currently open SSH connections without successful authentication. HTTP asset/discovery connections are not unauthenticated SSH connections. |
| `bifroest_connections_rejected_total` | Counter | Admissions rejected by connection, per-session, tunnel, WebSocket or SSH protection limits; bounded `transport` and `reason`. SSH reasons include `startups`, `connections`, `channels`, `channels_per_connection`, `sessions_per_connection`, `reverse_forwards` and `reverse_forwards_per_connection`. `ssh_tunnel` distinguishes SSH limits reached through a tunnel from direct `ssh`. Global SSH-library limits apply per serving listener; Bifröst's connection budget remains aggregated. |
| `bifroest_connections_closed_without_authentication_attempt_total` | Counter | SSH connections closed without offering an authentication method other than `none`, with `reason`: `peer_closed`, `timeout`, `protocol_error` or `closed`. A public-key offer counts as an attempt, not necessarily a success. Not applied to ordinary HTTP traffic. |
| `bifroest_session_connections_active` | Gauge | Registered live authenticated SSH and browser-terminal connections, per flow. |
| `bifroest_sessions_active` | Gauge | Distinct Bifröst sessions referenced by those live connections, per flow. Not all retained sessions in storage. |
| `bifroest_tasks_active` | Gauge | Running shell, command and subsystem tasks, per flow; not Bifröst sessions or idle SSH session channels. |
| `bifroest_authentication_flow_evaluations_total` | Counter | Provider evaluations per flow, with `transport`, `method`, `phase`, `result` and `error_category`. An accepted `public-key`/`candidate` is only an eligibility probe. |
| `bifroest_authentication_flow_evaluation_duration_seconds` | Histogram | Duration of those evaluations, excluding observer/audit work. Interactive authentication includes user waiting time. |
| `bifroest_authentication_completions_total` | Counter | Explicit authentication completion/compatibility decisions, with `transport`, `method`, `result` and `error_category`. This is not a count of published browser credentials or established SSH handshakes. |
| `bifroest_authentication_attempts_total` | Counter | Once per authentication attempt result, not per evaluated flow; `transport`, `method` and `result` (`success`, `denied`, `error` or `abandoned`). Public-key eligibility, polling and discovery are not successes or separate logins. Failed attempts without one resolved flow have empty flow labels. |
| `bifroest_access_denials_total` | Counter | Post-login PTY, forwarding, subsystem/task and management-policy denials, with fixed `operation` and bounded `reason`. Not every HTTP `401`/`403` is a policy denial or failed login. |
| `bifroest_auditlog_enabled` | Gauge | `1` for a configured logger not disabled after a best-effort failure. |
| `bifroest_auditlog_disabled` | Gauge | `1` when a configured logger was disabled after a best-effort failure. No series is invented for an unconfigured logger. |
| `bifroest_recording_configured` | Gauge | Whether recording is configured for the audit log, independently of later failures. |
| `bifroest_auditlog_errors_total` | Counter | Failures reported to the logger's failure policy, with bounded `error_category`. |
| `bifroest_recording_errors_total` | Counter | Recording failures; these can also increment the enclosing audit-log error counter. |
| `bifroest_recording_spool_bytes` | Gauge | Accounted spool bytes, including outstanding storage reservations. Omitted when accounting is unavailable or uncertain. |
| `bifroest_recording_spool_limit_bytes` | Gauge | Configured spool limit. |
| `bifroest_recording_spool_accounting_valid` | Gauge | Whether spool usage is available and trustworthy. |
| `bifroest_auditlog_minimum_free_bytes` | Gauge | Configured journal filesystem free-space reserve, not measured filesystem free space. |
| `bifroest_auditlog_available_bytes` | Gauge | Last measured space available on the journal filesystem; not the recording spool. Use only with a valid, recent space observation. |
| `bifroest_auditlog_space_observation_valid` | Gauge | Whether the latest journal-space observation succeeded. Overdue observations and a stopped observer report `0`. Failed observation does not change the audit failure policy. |
| `bifroest_auditlog_space_observation_timestamp_seconds` | Gauge | Unix timestamp of the last successful space observation, sampled approximately every 15 seconds. |
| `bifroest_auditlog_details_suppressed_total` | Counter | Unauthenticated audit details aggregated or suppressed, with `reason="rate_limit"` or `reason="journal_reserve"`. Counts details, not summary records. |
| `bifroest_remote_delivery_errors_total` | Counter | Worker retry failures, including delivery and local-state failures. |
| `bifroest_remote_delivery_worker_pending` | Gauge | `1` while a sequential worker has an observed outstanding delivery; otherwise `0`. Not a complete backlog count. |
| `bifroest_remote_delivery_pending_observed_seconds` | Gauge | Time since the worker first observed its current outstanding delivery. Not the oldest stored artifact's age; resets when that operation resolves. |
| `bifroest_cleanup_runs_total` | Counter | Cleanup attempts with `operation` and `result`, including individually handled failures. |
| `bifroest_cleanup_last_run_success` | Gauge | Whether the last observed operation succeeded, per cleanup label set. |
| `bifroest_cleanup_last_success_timestamp_seconds` | Gauge | Unix timestamp of the last successful operation since process start. |
| `bifroest_cleanup_problems` | Gauge | Unresolved session inspection/cleanup problems observed during the last housekeeping scan, per flow. An empty flow groups unknown/removed flows. |
| `bifroest_cleanup_last_scan_timestamp_seconds` | Gauge | Time of the last housekeeping observation, including failed scans; use it to identify stale problem counts. |

Flow evaluation results are `accepted`, `denied` or `failed`; completion results are `success`, `denied` or `failure`. These measurement points are separate and must not be added together as login counts. No-matching-flow attempts do not invent a flow evaluation or completion. Public-key phases are `candidate` and `verified`; other ordinary methods use an empty phase.

Transports identify SSH (`ssh`) versus browser authentication (`http`); SSH tunnels remain `ssh`. Error categories are `system`, `config`, `network`, `user`, `permission`, `expired` or `unknown`; successful observations use `unknown`. Cleanup operations are `housekeeping`, `session_inspection`, `session_dispose`, `session_delete`, `orphan_cleanup` and `recording_retention`. A successful overall housekeeping pass does not erase a failed individual operation's series. Problem counts are observations, not a full inventory if a scan failed. Unknown/removed flow names are not exported.

### Active ages

The following are gauges, not completed-lifetime histograms. For each prefix, `_age_observations` counts known live creation times and `_age_sum_seconds` is their combined age; `_oldest_age_seconds`, `_youngest_age_seconds` and `_average_age_seconds` describe their current ages. With no known live creation times, count and sum are zero and extrema/average are absent. Age is not idle time.

| Prefix | Scope |
| - | - |
| `bifroest_sessions` | Active sessions per flow. Age starts at the original session creation, including after reconnecting. |
| `bifroest_session_connections` | Registered live authenticated connections per flow. Reconnecting starts a new connection age. |
| `bifroest_connections` | Connection age with `transport="ssh"` or `transport="http"`. HTTP includes physical TLS sockets and hijacked WebSockets; SSH includes logical SSH tunnels. Do not add these layers together. |

For a weighted average across instances, divide the sum of `_age_sum_seconds` by the sum of `_age_observations`, rather than averaging per-instance averages. A retained session without a live registered connection is not active. Scraping does not scan session storage.

### Workload HTTP, TLS and channels

These metrics exclude the monitoring listener, its scrapes and its health probes. Requests, physical sockets and long-lived channels are separate: HTTP/2 multiplexes requests on one socket; an SSH tunnel also owns a logical SSH connection. HTTP metrics use only fixed route names/groups, known methods and bounded status codes. Unrecognized paths use `route="unknown"`; unrecognized methods use `method="unknown"`. Raw paths, queries, Origins and peer addresses are never labels. Request `flow` is empty until a verified flow is actually known; physical HTTP sockets are never assigned a flow.

| Metric | Type | Meaning |
| - | - | - |
| `bifroest_http_connections_opened_total` | Counter | Accepted physical HTTP/TLS sockets. |
| `bifroest_http_connections_active` | Gauge | Open sockets, including hijacked WebSockets until their actual transport closes. |
| `bifroest_http_connections_closed_total` | Counter | Socket closures with bounded I/O/end `reason`. |
| `bifroest_http_tls_handshakes_total` | Counter | `result="success"` or `result="aborted"`, with a bounded reason for aborted handshakes. Includes failed or timed-out handshakes before any HTTP request. |
| `bifroest_http_requests_total` | Counter | Requests reaching the HTTP handler, including authority, path and origin rejections, with `route`, `method`, `status` and known `flow`. Malformed HTTP rejected before handler dispatch is not a request observation. |
| `bifroest_http_requests_active` | Gauge | Currently executing handlers, including streams, by `route` and `method`. |
| `bifroest_http_request_duration_seconds` | Histogram | Ordinary handler duration. Successfully opened WebSockets, SSH streams and dedicated artifact transfers are excluded. |
| `bifroest_http_transfer_duration_seconds` | Histogram | Dedicated HTTP artifact-transfer duration, separate from ordinary API latency and WebSocket channel lifetime. |
| `bifroest_http_request_body_bytes_total` / `bifroest_http_response_body_bytes_total` | Counter | Read/written HTTP body bytes; excludes TLS/framing overhead and hijacked WebSocket frames. Uses the request labels. |
| `bifroest_http_rejections_total` | Counter | Security/protection-budget rejections, with `route` and fixed `reason`, including authority, origin, CSRF, body, request/login, socket and message/wire budgets. |
| `bifroest_http_channels_opened_total` / `bifroest_http_channels_active` | Counter / Gauge | Opened/current terminal or management WebSockets and SSH tunnels, with `kind`. Opening the transport does not prove successful in-channel authentication. |
| `bifroest_http_channel_open_failures_total` | Counter | Requests to channel routes that did not open a channel, with `kind` and HTTP `status`. |
| `bifroest_http_channels_closed_total` | Counter | Channel endings with `kind` and bounded `reason`; an established channel may still fail authentication or protocol validation. |
| `bifroest_http_channel_duration_seconds` | Histogram | Open channel lifetimes, separate from ordinary API latency. |
| `bifroest_http_tls_certificate_expiration_timestamp_seconds` | Gauge | Earliest Unix expiry time in the currently published certificate chain, per configured `domain`. |
| `bifroest_http_tls_renewal_errors_total` | Counter | Failed renewal rounds of the existing HTTP certificate manager. Does not enable ACME on monitoring. |

Rising rejection or handshake-abort rates can indicate scans, slow clients or overload, but also ordinary health checks and client/network failures. Use rates and sustained error ratios together with audit logs; these metrics are not an IDS and must not trigger liveness restarts merely because an external backend fails.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |

## Examples

Add this block to an existing Bifröst configuration to enable loopback-only monitoring on port `9090`:

```yaml
monitoring:
  enabled: true
```
