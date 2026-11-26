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

## CI runtime grouping

CI runs the `local`, `docker` and `ssh` suites in one shared runtime job. It
prepares the toolchain, dependencies, browser assets and Chromium once, then runs
all three suites with Docker followed by all three with Podman. Every suite has
its own CI step and result; a failure does not skip later suites. Later suites
reuse Go's on-runner compilation cache, not fixture binaries,
credentials, containers or runtime-specific image storage. Every fixture still
builds from the checkout with its own version and isolated state.

The kind job follows the same ordering. Docker runs on pull requests, schedules
and manual dispatches; Podman remains schedule/manual-only. A Docker test failure
does not skip Podman, but either failure still fails the job. Browser JSON and
runtime diagnostics use separate `var/e2e/docker` and `var/e2e/podman` paths.
Individual Go test deadlines and test selections are unchanged; combined jobs
allow the sum of their previous job budgets.

This reduces the original runtime jobs from six to one, plus two kind jobs to one on
schedule/manual runs. It trades parallel runtime execution for less duplicated
setup and fewer runner slots. Compare queue time, job duration and total runner
minutes in CI; a longer combined job is not by itself a regression. The overall
workflow need not finish faster if runner capacity is unconstrained.

Go's reported package/test duration includes fixture builds, image preparation
and cleanup, but excludes compilation of the test executable before it starts.
Do not attribute the whole gap between parent and subtest times to compilation.
Docker and Podman still prepare their own images; their image caches are separate.
The existing cross-job cache policy is unchanged.

The combined jobs have new check names. If branch protection explicitly requires
the previous per-runtime checks, update that configuration before merging.

The native GitHub runner validation and remaining optimization candidates are
recorded in the [CI performance review](../ci-performance-review.md).

### Mandatory browser tasks

After preparing the pinned frontend, Chromium and Linux network-isolation tools,
run the same commands locally as CI:

```sh
BIFROEST_E2E_RUNTIME=podman mise run test:e2e:docker:browser
BIFROEST_E2E_RUNTIME=podman mise run test:e2e:kubernetes:browser
```

Select `docker` instead to use Docker. The tasks invoke the tested Go runner in
`test/e2erunner`, which resolves the pinned Node executable and enables browser
execution. It streams `go test -json`, retains separate runtime/suite logs, and
requires every selected top-level test to pass exactly once. Any skipped test
(including subtests), failed test/build, missing result, malformed JSON, process
failure or incomplete package result fails the task. The actual E2E assertions
remain in `test/e2e`; no test-result verification is embedded in workflow YAML.
Test the runner without Chromium or a container runtime with:

```sh
go test ./test/e2erunner
```

## Additional integration suites

For installed curl transport probes, run `mise run test:e2e:curl`. See [tested and probably working curl versions](../curl/README.md) for the recorded results, expected baselines and required-profile settings.

For the built monitoring listener and a real local Prometheus, provide `prometheus` and `promtool` on PATH (or set `BIFROEST_E2E_PROMETHEUS` and `BIFROEST_E2E_PROMTOOL` to their executable paths), then run `go test -tags=e2e -run '^TestMonitoring(PrometheusIntegration|DocumentedPrometheusAlerts)$' -timeout=10m ./test/e2e`. No container runtime is required. The tests build the current checkout, bind only loopback addresses, verify OpenMetrics ingestion, TLS/token negative controls and every alert rule extracted directly from the monitoring guide. Missing tools skip these optional tests; explicitly configured but unavailable tools fail. Process logs are retained under `var/e2e/monitoring-*`.

Run `go test -tags=e2e -run '^TestMonitoringManagementCLI$' -timeout=10m ./test/e2e` to test the built CLI and direct SSH with management-only metric collection, no HTTP monitoring listener, and intentionally missing disabled token/TLS files. It covers all three output formats, default-table behavior, exact multi-family filtering and absent/unknown families. It needs neither Prometheus nor a container runtime.

Run `mise run test:e2e:tunnel` for the built server with real OpenSSH, curl and SFTP against an isolated container backend. It requires an owned Docker/Podman runtime and tests HTTPS/1.1, HTTP/2 and WSS without a direct SSH listener or WebUI. Under WSL it also requires and tests native Windows OpenSSH, curl and SFTP over HTTPS/1.1. TLS and SSH host-key checks remain enabled. macOS must run this suite natively before claiming native macOS coverage.

Windows curl 8.22.0/Schannel fails concurrent WSS duplex even in the independent curl probe, causing SSH MAC failures. The Windows-WSS profile is explicitly skipped by default, not claimed as passing. With another/fixed Windows curl build, set `BIFROEST_TEST_TUNNEL_WINDOWS_WSS=1` to make it mandatory. The standalone probe's `BIFROEST_TEST_CURL_REQUIRE=wss-empty-close` likewise requires concurrent WSS, not merely alternating transfers.

## Browser tests on Linux

Shared Docker/Kubernetes browser tests require `pasta` from the `passt` package with `--splice-only` support (January 2026 or newer). CI installs the package. On Linux, Chromium runs in a private network namespace so Docker's host-interface changes cannot abort unrelated requests with `ERR_NETWORK_CHANGED`. Only the fixture's loopback TCP port is forwarded; real HTTPS, cold WASM loading, WebSockets and authentication remain unchanged, without request replay.

The system `/bin/sh` launcher uses a fixed `exec "$@"` script to start the pinned Node and temporary Go test binaries through Ubuntu's existing AppArmor execution transition. Executable paths and arguments remain positional, without shell evaluation. The profile remains enabled and unchanged.

Check namespace isolation and authenticated TLS forwarding without starting a container runtime:

```sh
go test -tags=e2e -run '^TestSharedBrowserNetwork' ./test/e2e
```

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
