---
description: Interpret offline test packages, measured durations and the shared text, JSON and JUnit outcomes.
---

# Reports

Text, JSON and JUnit use the same completed result without reevaluating policy
or assertions. Process status is defined by [`bifroest test`](../cli/test.md#exit-codes).
An expected denial can be a passing test. An assertion mismatch remains a
failure, even when used deliberately to demonstrate reporting.

## Packages and ordering {: #packages }

Each physical directory containing suite candidates is a package. Explicitly
provided empty directories also appear. A single `tests/foo_bftest.lua` belongs
to `tests`; nested directories such as `tests/team` are separate packages,
not rolled into their parent.

Paths use forward slashes and are relative to the physical invocation directory
when possible. Symlinks retain physical identity and deduplication. Presentation
follows positional-root order, then directory order; source execution remains
sorted by canonical path.

## Text {: #text }

The default shows failing/error cases and one summary per package:

```text
=== RUN   deliberately-red-unix/wrong-target-contract
red-unix_bftest.lua:19: expected "not-alice", actual "mapped-alice"; reason "Deliberately red smoke test"
--- FAIL: deliberately-red-unix/wrong-target-contract (0.001s, 1 assertion)
FAIL    pkg/test/examples/ssh (0.004s, assertions: 1, passed: 0, failed: 1, skipped: 3)

RESULT: 0 PASSED, 1 FAILED, 3 SKIPPED
```

[`-v` / `--verbose`](../cli/test.md#test-flag-verbose) shows package, suite and test headers and every outcome,
indented four spaces per level. For example, running the OIDC examples:

```text
=== RUN   pkg/test/examples/oidc
    === RUN   assumed-oidc
        === RUN   device-mapped-identity
        --- PASS: device-mapped-identity (0.001s, 9 assertions)
        === RUN   code-mapped-identity
        --- PASS: code-mapped-identity (0.001s, 9 assertions)
    --- PASS: assumed-oidc (0.004s, assertions: 18, passed: 2, failed: 0, skipped: 0)
--- PASS: pkg/test/examples/oidc (0.004s, assertions: 18, passed: 2, failed: 0, skipped: 0)

RESULT: 2 PASSED, 0 FAILED, 0 SKIPPED
```

Times and source lines above illustrate the format; real locations follow the
current source. Names are unquoted. Assertion locations use filename and Lua
line; in-memory input uses `<memory>:LINE`. JSON retains full source paths.
Text is rendered after the run completes, not streamed as live test events.

### Counts and empty packages

The final result counts tests, not assertions or suite headers. `SKIPPED`
counts every declared test in a platform-excluded suite, before name filtering.
Name exclusions do not count as skips. Loading/runtime/selection errors add
`ERRORS` when nonzero; suite/package summaries also append `errors: N`.

Empty packages print `SKIP package: no tests found`; fully name-filtered packages
say `no tests selected`. Neither creates passes or declared skips. A mixed run
can pass if other tests ran, but an entirely empty/excluded selection still
returns 2 and prints an explicit error.

Warnings/operational diagnostics go to stderr. Completed reports do not emit a
redundant generic executable error log. Real invocation, report-write and
independent cleanup failures remain visible.

## Measured durations {: #durations }

The Go runner measures wall time once, outside Lua; text shows three decimal
places. Tests include fresh VM/replay/evaluation/verification, suites include
loading/configuration, and packages sum time spent on their own sources, not
descendants. Total time additionally includes discovery. Serialization is
excluded. No Lua clock is exposed and no execution duration is invented for
platform-excluded tests. JSON `durationSeconds` and JUnit `time` use the same
observations.

## JSON {: #json }

[`--json PATH`](../cli/test.md#test-flag-json) writes the shared report model:

| Field | Meaning |
| --- | --- |
| `apiVersion`, `scope` | Report format version and limited offline boundary. Suite declarations do not contain an `apiVersion`. |
| `packages`, `suites` | Physical package identity and suite/source metadata, including declared test counts. |
| `results` | Per-test package, suite, source, name, status, assertion count, failure details and categorized errors. |
| `durationSeconds` | Measured run/package/suite/test time where available. |
| `warnings` | Source warnings, separate from test errors. |
| `skippedSuites` | Excluded suites, their reason, declared `tests` and `testNames`. |
| `summary` | `passed`, `failed`, `skipped`, `errors` test counts. |
| `suite` | Singular name only when exactly one suite registered. |

Platform exclusions are not passing result records. An empty selection adds a
summary error even if all declarations were platform-excluded.

## JUnit XML {: #junit-xml }

[`--junit PATH`](../cli/test.md#test-flag-junit) writes a `testsuites` root.
Suites are grouped by physical source path and suite name. Cases keep their
declared names; counts represent tests, not assertions.

- Passed cases have no status child. Assertion failures use one
  `failure type="assertion"` containing all failures, expected/actual values,
  optional reasons and source/line. Execution/loading errors use `error` with
  the retained category and prior assertions in its body. A case never has both.
- `file` retains the source path; `line`, when known, is the first assertion
  failure. Other locations remain in the body. Unknown locations, absent
  timings/timestamps and in-memory filenames are not invented.
- Platform exclusions produce `skipped` with actual declared names/reason before
  name filters. An empty selection additionally emits `no-tests-selected` as an
  error. Warnings are preserved in `system-err`.
- Properties include `apiVersion`, `scope`, `authenticationAssumed=true`, source
  and measured suites' physical `package`. This is not proof of authentication
  or complete authorization.
- Markup is escaped. XML 1.0-forbidden code points/invalid UTF-8 are spelled out
  as `\u…` / `\x…`, not silently replaced.

For the separate Go reporting API, see the
<<asset_link("pkg/test/README.md", "package documentation")>>.

## Report files {: #report-files }

Existing **regular report files may be replaced**, and missing parents are
created. Symlinks, nonregular destinations, suite filenames, captured inputs
and their aliases remain protected. JSON/JUnit destinations must differ.

The CLI writes text, then JSON, then JUnit; this is **not a multi-file atomic
transaction**. A later failure returns 2 and leaves earlier reports intact.
Each file is serialized privately beside its target, then renamed into place;
serialization/close failure leaves an old destination intact and temporary files
are cleaned up. The diagnostic keeps the report path and original cause.
This is not a crash-durability or hostile-filesystem sandbox guarantee.
