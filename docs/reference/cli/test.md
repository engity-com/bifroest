---
description: Run offline Lua configuration tests, select cases and write text, JSON or JUnit results.
---

# `bifroest test`

Run offline tests against YAML configuration without starting the service,
authenticating credentials or creating target resources. The current testing
scope is limited; `selected` is not a complete access grant.

To write a suite, start with [Test a configuration](../../guides/testing.md).
The [testing reference](../testing/index.md) describes the Lua API and supported
policy behavior separately from this command's invocation.

## Syntax

<<cli_syntax("test", "[flags] <suites>...")>>

## Arguments

### `suites` {: #argument-suites }

One or more suite files or directories. Directories are searched recursively for
`*_bftest.lua`. File/directory symlinks are followed, **including outside the
starting directory**; physical inputs are deduplicated and directory cycles
terminate. Sources execute in sorted canonical-path order. `--suite` is not a flag.

A valid matching Lua file that registers no suite produces a warning on stderr;
syntax/runtime/resource failures are errors, even when filters select no tests.

## Flags {: #test-flags }

Includes [general executable flags](index.md#general-flags).

<<flag("configuration", "File Path", "../data-type.md#file-path", aliases=["c"], id_prefix="test-", heading=3)>>
Fallback YAML file for suites without `configuration`; relative to the invocation
directory. Otherwise the [platform configuration path](usage.md#configuration)
is used. This does not override suite YAML. See [configuration selection](../testing/suites.md#configuration).

<<flag("includes", "string", id_prefix="test-", heading=3)>>
Repeatable Go regular expression matched against `suite.name/test.name`.
Includes are OR-combined; without includes, all names match. Matching is by
substring unless anchored. Invalid expressions and an empty final selection
return 2. Filters choose tests, not which candidate source files are loaded.

<<flag("excludes", "string", id_prefix="test-", heading=3)>>
Repeatable name filter using the same syntax. Any matching exclusion wins over
includes. Name exclusions are not platform-skipped outcomes.

<<flag("verbose", "bool", default=False, aliases=["v"], id_prefix="test-", heading=3)>>
Show every package, suite and test, including passing and platform-skipped cases.
Without it, show failures/errors and per-directory summaries.

<<flag("json", "File Path", "../data-type.md#file-path", id_prefix="test-", heading=3)>>
Write the [JSON report](../testing/reports.md#json), replacing an existing regular
report and creating missing parent directories.

<<flag("junit", "File Path", "../data-type.md#file-path", id_prefix="test-", heading=3)>>
Write the [JUnit XML report](../testing/reports.md#junit-xml), with the same
replacement/parent behavior. JSON and JUnit need distinct destinations. Symlinks,
nonregular destinations, reserved suite filenames and captured inputs/aliases
are protected. Multiple outputs are [not an atomic transaction](../testing/reports.md#report-files).

## Output

Text goes to stdout; warnings and operational diagnostics go to stderr. The
final `RESULT` counts tests, not assertions. Physical source directories form
packages, including for single-file runs. See [reports](../testing/reports.md)
for package ordering, verbose output, timings and skip/error representation.

### Exit codes {: #exit-codes }

| Code | Meaning |
| --- | --- |
| `0` | At least one test selected; all selected tests passed without loading errors. |
| `1` | At least one assertion failed. |
| `2` | No tests found/selected, invalid input/regex, unsupported or unmodeled dependency, policy/runtime/resource/report failure. |

Code 2 takes precedence over 1. A report failure retains its destination and
original cause, even after text has been printed. Completed result reports do
not cause a redundant generic executable error log.

## Examples

### Test your configuration and publish CI reports

```shell
bifroest test tests \
  --configuration configuration.yaml \
  --json reports/testing.json \
  --junit reports/testing.xml
```

### Select cases across directories

```shell
bifroest test tests/team-a tests/team-b/access_bftest.lua \
  --configuration configuration.yaml \
  --includes '^ssh/' \
  --includes '^ops/' \
  --excludes '/legacy$' \
  --verbose
```

### Run the repository examples

From a checkout, with its current binary:

```shell
bifroest test pkg/test/examples --excludes '^deliberately-red-'
```

Without the exclusion, the deliberate failure returns 1. See the
<<asset_link("pkg/test/README.md", "example catalogue")>> for individual directories.

## Availability

<<cli_availability(local=True, remote=False, direct_ssh=False)>>

The CLI uses its own OS/architecture/version metadata for
[platform selectors](../testing/suites.md#platform). There are no platform
override flags. It also runs in the regular Bifröst image; see the
[container example](../testing/isolation.md#container-execution).
