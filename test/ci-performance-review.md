# CI performance review — 2026-11-26

## Validated first experiment: sequential container runtimes per suite

The first experiment in `.github/workflows/e2e.yml` kept one job per suite,
with Docker followed by Podman, instead of a suite/runtime Cartesian product.
This is the three-job baseline for the single-job follow-up below. The combined
kind job retains schedule/manual-only Podman coverage.

[Validation run 45779692282](https://github.com/engity-com/bifroest/actions/runs/45779692282)
at `d8bb2a667cde1ccf1c2c227799bc4e0d5f8e0aaf` passed all seven executing jobs,
including both runtime variants of the Docker and Kubernetes browser tests.
The PR-only file detector was skipped as intended.

Comparison with
[successful PR run 45775881406](https://github.com/engity-com/bifroest/actions/runs/45775881406):

| Suite | Previous two jobs, summed | Combined job | Reduction |
| --- | ---: | ---: | ---: |
| Local | 11:45 | 5:03 | 57.0% |
| SSH | 9:59 | 6:32 | 34.6% |
| Docker, including browser | 16:56 | 11:23 | 32.8% |
| **Total** | **38:40** | **22:58** | **40.6%** |

Times are minutes:seconds of unweighted runner occupancy, not billing minutes
or parallel workflow wall time. Against another successful run, 45680173855,
the same total reduction is 39.2%. These are historical comparisons with
different source commits and runner conditions, not controlled A/B trials.

In the combined run, the Docker/Podman native suite steps took respectively
3:44/0:34 for Local, 5:07/0:36 for SSH, and 6:29/1:51 for Docker. Tests really
executed; this is not replay of cached test results.

The complete manual workflow took 18:36. It includes kind/Podman coverage absent
from the comparison PR runs, so comparing only complete workflow duration would
be misleading. Queue relief is also not established by this single run: all
seven jobs started about three seconds after dispatch.

## Follow-up experiment: one runtime job for Local, Docker and SSH

The current implementation removes the remaining suite matrix. One runner
prepares the frontend before fixture compilation, then executes Local, Docker
and SSH with Docker, followed by the same three suites with Podman. Browser
verification still runs once with each runtime. Independent step conditions
require successful shared setup but do not hide later suites after a test
failure. Authorization, PAM, Darwin and kind remain separate.

Browser result verification is now a Go tool, `test/e2erunner`, invoked through
`test:e2e:docker:browser` and `test:e2e:kubernetes:browser`. Its unit/process tests
cover missing, duplicate, skipped, failed, malformed and incomplete test results,
nonzero exits, cancellation and separate runtime logs. Workflow YAML contains
only the task invocation, not Python assertions.

Compare the native GitHub run against both the first experiment above and
[three-job PR run 45791273611](https://github.com/engity-com/bifroest/actions/runs/45791273611):
Local 4:41, SSH 4:20 and Docker/browser 13:38, totaling 22:39 of runner occupancy.
Native validation of the single-job follow-up is pending. Report runner-time
savings separately from the longest-job and complete-workflow durations; fewer
runner slots can reduce queue pressure without guaranteeing a faster workflow.

## Next candidates — investigated, not implemented

The normal CI sample below is
[run 45775881516](https://github.com/engity-com/bifroest/actions/runs/45775881516).
Its executing jobs consumed about 166 unweighted runner-minutes. Job timestamps,
uploaded Go JSON reports and cache messages were inspected together.

### 1. Compile the built-browser test executable once before shard fan-out

Locations: `.github/workflows/build.yml` (`test-browser`) and
`web/scripts/browser-go-tests.ts`.

- The three browser jobs occupied 7:05, 8:14 and 6:26, totaling 21:45.
- Their test steps totaled 20:03; actual test processes reported 9:44 combined.
- All three logged a Go build-cache miss. `go test -list` compiles the same
  `pkg/service` test executable independently before each shard selects tests.
- The existing shard workloads are already reasonably balanced: approximately
  3:14, 3:28 and 3:03 of actual test execution.

Recommended experiment: a single build stage produces an immutable test
executable from the exact browser assets and checkout, then the existing three
shards execute it with their complete verified test selections. Keep the expected
package working directory, environment, timeout, JSON/JUnit reports and fresh
browser/server fixtures. Do not serialize release binaries behind this new
test-only compilation stage.

Rough opportunity: remove two of three cold compilations, potentially several
runner-minutes. The 10:19 gap also contains command/startup overhead and is not
all proven compiler time. Artifact transfer, an additional scheduling stage and
older release-ref compatibility must be measured before claiming a net saving.

### 2. Make expensive Go cache snapshots available to new PRs

Locations: `.github/actions/cache-go/action.yml`,
`.github/workflows/ci.yml` and `.github/workflows/build.yml`.

At inspection time, all eight visible `go-build-*` snapshots belonged to PR
merge refs; none belonged to `main`. The inspected Windows test job and all
three browser shards explicitly logged build-cache misses. A cache key fallback
does not make another PR's merge-ref cache accessible. Also, the static core
writer and browser readers start in parallel: readers cannot restore a snapshot
that the writer has not saved yet.

Investigate a small, trusted default-branch warming path for the existing
expensive test contexts. Do not add writers to every binary/E2E/lint job:
repository cache usage was already about 10.5 GB, and persistence was explicitly
made opt-in to reserve space for expensive tests. Measure restore/save overhead,
hit rate and eviction pressure. Any retention cleanup or storage-budget change
needs a separate decision; this review does not delete caches.

### 3. Avoid standalone cold compilation for native policy checks

Locations: `.github/workflows/build.yml` (`test-policy`, `test-policy-oci`),
`test/policyci/main.go` and `test/policyci/oci.go`.

- The three native policy jobs occupied 3:59, 4:46 and 7:42, totaling 16:27.
  The additional Linux native/OCI parity job occupied 6:16.
- Each native job's eight JSON case reports sum to under 0.1 seconds of internal
  case duration. This excludes process startup, harness compilation, CLI
  compilation, report checks and tool setup; it is not total CLI wall time.
- Each job runs `go run ./test/policyci`, then builds `./cmd/bifroest` again.
  The harness package also imports the OCI/image implementation in native mode.
- The native harness uses `-trimpath`; normal package tests do not. Merely moving
  the steps together therefore does not guarantee reuse of compiled packages.

Recommended experiment: combine Linux native and OCI checks with the same
on-runner compiler cache, and evaluate placing each native policy check after
the existing same-platform host tests. Preserve distinct fresh output
directories, all negative cases, restricted environments and platform coverage.
Measure the extra critical-path time and align compatible build modes rather
than assuming all 16:27 can be removed.

### 4. Evaluate sharing preparation with authorization E2E

Locations: `.github/workflows/e2e.yml`, `mise.toml` and
`test/e2e/harness_test.go`.

The single-job follow-up above groups Local, Docker and SSH as requested, but
authorization still starts separately and builds overlapping Go packages. The
successful first experiment shows how small a later runtime becomes after
warming the compiler. Adding authorization is a separate potential experiment,
not part of the current suite grouping.

This could remove one more job, but it trades parallel feedback for less cold
compilation. Preserve every suite, authorization's pre-build/runtime budget
separation, fresh fixture state and execution of later suites after earlier
failures. Benchmark before choosing this over a shared compiler/test-build stage.

### 5. Remove identical host/target builds within a Linux fixture

Location: `test/e2e/harness_test.go`, `prepareBinaries`.

The full fixture mode currently invokes four builds. On a native Linux host,
the target OS/architecture and flags match the host builds, including the same
per-fixture version. Build each distinct target once and materialize a second
file only when needed; retain separate builds when platforms differ.

An illustrative local warm-cache check spent about 2.34 seconds on the duplicate
server build and 0.29 seconds on the duplicate helper build. This is not a
GitHub-runner saving estimate and is lower priority than repeated cold builds.
Keep fixture-specific versions/keys/state and update binary-selection/failure
regressions rather than introducing a shared cross-fixture executable.

## Do not optimize by removing coverage

The Linux native/CGO, static and race configurations are not interchangeable.
Neither are Darwin/Windows native execution, PAM policy, real browser restart,
Docker/Podman semantics or Kubernetes lifecycle tests. Keep their assertions and
deadlines. Prefer eliminating repeated compilation/setup and measuring the
runner-time versus critical-path trade-off.
