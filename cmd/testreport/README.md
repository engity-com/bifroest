# Go test reports

This stdlib-only CI tool runs the original command directly, without a shell or changes to its arguments, environment, test scope, retries or timeout.

```text
go run ./cmd/testreport run --output var/test-report/core -- go test -json ./cmd/testreport
go run ./cmd/testreport analyze --input var/test-report/core/raw.jsonl --output var/test-report/reanalyzed
```

`--output` contains:

| File | Content |
| --- | --- |
| `raw.jsonl` | Original stdout, including any non-JSON diagnostics |
| `stderr.log` | Original stderr (`run` only); also streamed to the console |
| `report.json` | Schema-versioned measurements, all observed cases/packages, warnings and optional baseline comparisons |
| `report.md` | CI summary with top slow cases/packages and measurement limits |

Go JSON `Output` events are streamed as human-readable console output. Reports are written even on command failure or cancellation, provided the output directory remains writable. The compiled tool preserves nonzero child exit codes; cancellation returns 130, and collection errors or incomplete/unknown JSON return nonzero even if the child exited zero. `go run` itself maps a nonzero program exit to 1. The child exit is recorded separately in `report.json`, when available.

Use `--top N` (default 15, maximum 100) to limit Markdown tables. Add `--baseline path/to/previous/report.json` to show positive mean-duration deltas and slow cases absent from comparable baseline data. These comparisons never introduce performance gates. Cached timings are marked as historical and excluded from timing aggregates and comparisons. Repeated cases are aggregated; nested subtests are listed but not double-counted in the top-level total.

The outside-package estimate is **not compile time**: it includes startup/scheduling/output overhead and cannot see compilation overlapping tests. CPU values use OS `ProcessState` accounting. Optional Linux/Darwin RSS is normalized to bytes and is an OS single-process peak, **not aggregate parallel RAM**; unavailable values are omitted. Analyze mode cannot reconstruct command wall time or resources. See each report's measurement limits before comparing runners or flags.

Cancellation kills the command's process group on Linux/Darwin and its Job Object on Windows. Windows starts the child suspended until job assignment; inability to establish containment fails closed. No runtime process-tree containment is promised on other platforms.

Only a bounded JSON line buffer (1 MiB) and per-case/package metrics are retained; raw logs stream to disk. Oversized/invalid records and unknown actions are retained in the raw artifact and cannot silently become passing results. The wrapper does not collect command arguments or environment variables. Raw stdout/stderr are unredacted test logs; apply the same secret-handling and artifact-retention rules as for existing CI logs.
