# Integration test builds

Run the authorization suite with the pinned MISE toolchain:

```sh
mise run test:e2e:authorization
```

Its `build:e2e:authorization` prerequisite compiles both fixture build modes
before the existing five-minute Go test deadline starts. A cold compiler cache
must not consume the authorization/OIDC execution budget. The deadline, complete
test selection, assertions and per-operation timeouts are unchanged.

The warm outputs under `var/e2e/authorization-build-cache` are **not** passed to
tests. Every fixture still builds its own binaries from the current checkout,
with its own version, keys, state and processes. Only Go's normal compilation
cache is warmed; no permission, credential, environment or workload is reused.
Calling `go test` directly bypasses this explicit build prerequisite.

The authorization suite does not require a container runtime. For suites that
do, select an owned working runtime explicitly, for example
`BIFROEST_E2E_RUNTIME=podman`; do not use an unrelated cluster or daemon.

For installed curl transport probes, run `mise run test:e2e:curl`. See [tested and probably working curl versions](../curl/README.md) for the recorded results, expected baselines and required-profile settings.

For the built monitoring listener and a real local Prometheus, provide `prometheus` and `promtool` on PATH (or set `BIFROEST_E2E_PROMETHEUS` and `BIFROEST_E2E_PROMTOOL` to their executable paths), then run `go test -tags=e2e -run '^TestMonitoring(PrometheusIntegration|DocumentedPrometheusAlerts)$' -timeout=10m ./test/e2e`. No container runtime is required. The tests build the current checkout, bind only loopback addresses, verify OpenMetrics ingestion, TLS/token negative controls and every alert rule extracted directly from the monitoring guide. Missing tools skip these optional tests; explicitly configured but unavailable tools fail. Process logs are retained under `var/e2e/monitoring-*`.

Run `go test -tags=e2e -run '^TestMonitoringManagementCLI$' -timeout=10m ./test/e2e` to test the built CLI and direct SSH with management-only metric collection, no HTTP monitoring listener, and intentionally missing disabled token/TLS files. It covers all three output formats, default-table behavior, exact multi-family filtering and absent/unknown families. It needs neither Prometheus nor a container runtime.

Run `mise run test:e2e:tunnel` for the built server with real OpenSSH, curl and SFTP against an isolated container backend. It requires an owned Docker/Podman runtime and tests HTTPS/1.1, HTTP/2 and WSS without a direct SSH listener or WebUI. Under WSL it also requires and tests native Windows OpenSSH, curl and SFTP over HTTPS/1.1. TLS and SSH host-key checks remain enabled. macOS must run this suite natively before claiming native macOS coverage.

Windows curl 8.22.0/Schannel fails concurrent WSS duplex even in the independent curl probe, causing SSH MAC failures. The Windows-WSS profile is explicitly skipped by default, not claimed as passing. With another/fixed Windows curl build, set `BIFROEST_TEST_TUNNEL_WINDOWS_WSS=1` to make it mandatory. The standalone probe's `BIFROEST_TEST_CURL_REQUIRE=wss-empty-close` likewise requires concurrent WSS, not merely alternating transfers.

## Owned workload shell and cursor-report regression

The pinned Alpine workload contains BusyBox 1.37.0. Its original `read_key()`
can consume a command's first ten bytes when `ESC[1;5R` is immediately followed
by user input: the known-key matcher has already read the complete report, but
the cursor-report parser reads again before checking it. This is reproducible
on a direct PTY without Bifröst, SSH, WebSockets or a browser. A visible prompt
does not repair the parser, and an occasional passing E2E run is not a fix.

The explicitly approved, test-image-only patch
`testdata/busybox/read-key-cursor.patch` checks that already buffered report
before reading more. It does not change key mappings, byte order, timeouts,
terminal responses or Bifröst production code. The upstream 1.37.0 source
archive is pinned by SHA-256, built with the base image's BusyBox configuration,
then rebuilt with this one patch. Only the test image's `sh`/`ash` symlinks use
the corrected binary; the original Alpine applets remain available.

Every shared Docker/Kubernetes workload image must pass a direct PTY regression
at build time, as the unprivileged fixture user, before Bifröst starts:

- Both the original Alpine binary and the rebuilt **unpatched** source must
  reproduce the original prefix loss (mandatory negative controls).
- The same build with the patch must execute the complete immediate command
  and preserve its actual outer-shell exit status in ten cases, including
  fragmented input, other/boundary cursor positions, UTF-8 and Ctrl/Alt arrows.

There are no retries, pacing delays, response filters or relaxed browser/audit/
recording assertions. Source archive, GPL-2.0-only patch, original/effective
configuration and the build recipe stay in the test image under
`/usr/local/share/e2e-busybox/`. They do not enter Bifröst release artifacts.
This local test-image patch is not claimed to be an accepted upstream fix;
external workloads using an affected BusyBox still require their own correction.
