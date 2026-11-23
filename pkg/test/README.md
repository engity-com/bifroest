# Testing

This package implements Bifröst's bounded offline configuration tests. It shares
production flow selection, principal mapping and SSH/local target projection;
authentication outcomes and environment facts are supplied by each test.
`selected` does not mean successful login or complete access authorization.

## Documentation

- [Write your first test](../../docs/guides/testing.md).
- [Lua API](../../docs/reference/testing/lua.md): functions and values.
- [Data types](../../docs/reference/testing/data-types.md): shared value types
  linked directly from properties.
- [Tests](../../docs/reference/testing/tests.md): individual cases and their
  input/verification properties.
- [Testing reference](../../docs/reference/testing/index.md): typed Suite/Test,
  input, context and result properties; account/OIDC data, reports and limits.
- [`bifroest test` command](../../docs/reference/cli/test.md): arguments, flags
  and exit codes.
- [Optional editor hints](types/README.md) for GoLand Lua plugins and LuaLS.

## Runnable examples

Run from the repository root with the current Bifröst binary:

```text
bifroest test pkg/test/examples --excludes '^deliberately-red-'
bifroest test pkg/test/examples/oidc --verbose
bifroest test pkg/test/examples --excludes '^deliberately-red-' --json var/testing/result.json --junit var/testing/result.xml
```

| Directory | Covers |
| --- | --- |
| [examples/ssh](examples/ssh/README.md) | SSH target selection, mapped local accounts, Unix/Windows variants and deliberate assertion failures. |
| [examples/oidc](examples/oidc/README.md) | Assumed verified Device Authorization/Code identities and separate artifact snapshots. |
| [examples/http](examples/http/README.md) | Logical HTTP requests, canonical origins and published-flow binding. |

The passing aggregate has 11 passed and 3 platform-skipped tests. Without the
exclusion, one deliberate failure returns 1. Platform exclusions are selected
from the binary's metadata; they are not native execution evidence for another OS.

## Go embedding

```go
import bftest "github.com/engity-com/bifroest/pkg/test"

report := bftest.RunPaths(ctx, []string{"./tests"}, bftest.Options{
    Platform: bftest.Platform{Version: "development"},
})
err := report.Err()
```

`RunSourcesWithOptions(ctx, luaBytes, fallbackYAML, options)` supports in-memory
suites without a file capability; `RunSources` is its default-options wrapper.
Unspecified OS/architecture use Go's runtime. A matching version selector needs
an explicit version from the embedding caller. Overrides affect suite selection,
not OS emulation. Reports support `WriteText`, `WriteTextWithOptions`, `WriteJSON`
and `WriteJUnit`.

When constructing reports directly, keep outcomes consistent and supply excluded
`TestNames` matching `Tests`. `WriteJUnit` rejects contradictory or incomplete
reports before writing XML.

The CLI adapter remains in `pkg/cli/test`. Prerequisites and commands for repository
native/container comparison checks are documented in
[`test/policyci`](../../test/policyci/README.md), not part of the Lua API. The
existing synthetic report identity `bifroest.policytest.runner` is retained for
report compatibility; the Go import path and package name are `pkg/test` / `test`.
