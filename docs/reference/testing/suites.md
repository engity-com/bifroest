---
description: Properties of a Lua test suite, including its tests and platform selectors.
---

# Suites {: #suite }

A suite groups tests sharing a YAML configuration and environment facts.
Register it with [`suite(definition)`](lua.md#function-suite) in a file named
`*_bftest.lua`. Each entry in `tests` is a [Test](tests.md); the suite's
[Platform](#platform) object is documented on this page.

## Properties

<<property("name", "Name", "data-types.md#name", required=True, heading=3)>>
The suite's name in reports and filters.

<<property("configuration", "string", optional=True, heading=3)>>
Optional YAML **content**, not a filename. Omit it to test the file selected by
`bifroest test --configuration PATH` or the normal configuration fallback.
Use this property for a suite that deliberately has its own fixture, for example
`file_content("configuration.yaml")` reading beside the suite. Explicit content
takes precedence over the CLI fallback. Empty or invalid content is an error,
not a request to try a different source; see [configuration selection](#configuration).

<<property("environment", "Environment facts", "local.md#environment", required=True, heading=3)>>
An object describing known users, groups and absences. These are test facts,
not an environment backend to start. Use `object {}` if no facts are needed.

<<property("tests", array_ref("Test", "tests.md#test"), required=True, heading=3)>>
An ordinary Lua array of 1–64 test tables with consecutive keys starting at 1.
Each entry supplies an input and a function that checks the calculated result.
Use `{ ... }`, not the read-only `list` helper, for this declaration array.

<<property("platform", "Platform", "#platform", optional=True, heading=3)>>
A table restricting this suite to particular Bifröst binaries. Omission imposes
no restriction; see the [Platform properties](#platform).

## Platform {: #platform }

A plain Lua table selecting **Bifröst binaries**, not targets or SSH clients.
The CLI uses its own build metadata and has no platform override flags.

Alternatives within one property are OR-combined; supplied properties are
AND-combined. Omitted properties match everything; an explicit empty array
matches nothing. Each array accepts at most 64 selectors.

<<property("os", array_ref("OS selector", "data-types.md#os-selector"), optional=True, id_prefix="platform-", heading=3)>>
Binary operating systems to match, for example `linux`, `darwin` or the group `unix`.

<<property("arch", array_ref("Architecture selector", "data-types.md#architecture-selector"), optional=True, id_prefix="platform-", heading=3)>>
Binary architectures to match, for example `amd64` or `arm64`.

<<property("version", array_ref("Version selector", "data-types.md#version-selector"), optional=True, id_prefix="platform-", heading=3)>>
Binary versions to match, for example `1.2`, `[1.3.5,1.4.0)` or `development`.

## Examples

This is a complete suite for the configuration in [the first-test guide](../../guides/testing.md#configuration).
Save it under `tests`, then run `bifroest test tests --configuration configuration.yaml`
from the directory containing that configuration file:

```lua title="tests/reference_bftest.lua"
suite {
  name = "ssh-target",
  platform = { os = { "unix" } },
  environment = object {
    accounts = list { object { name = "alice", uid = 1001 } },
  },
  tests = {
    {
      name = "selected-user",
      input = object {
        request = object { requestingName = "ops" },
        authentication = object {
          primary = object { outcome = "allow", account = "alice" },
        },
      },
      verify = function(t, actual)
        t:IsEqual("selected", actual.decision)
        t:IsEqual("primary", actual.flow)
      end,
    },
  },
}
```

To restrict `platform` further, use a table such as:

```lua
local supportedBinaries = {
  os = { "unix" },
  arch = { "amd64", "arm64" },
  version = { "1.2", "development" },
}
```

Use `supportedBinaries` as the value of `suite.platform`.

## Configuration fallback {: #configuration }

For each suite, use the first applicable source:

1. Its `configuration` content, when supplied.
2. [`--configuration PATH`](../cli/test.md#test-flag-configuration), relative to
   the invocation directory.
3. The normal [platform configuration file](../cli/usage.md#configuration).

The flag is a fallback, not an override. An unreadable/invalid chosen source
fails instead of trying the next one. The shared fallback is read at most once,
only when a selected test needs it. Loading starts no service or provider.

<span id="file-content"></span>
For the separate rules governing `file_content`, see [the function reference](lua.md#function-file-content).

## Platform skips and declaration errors

A mismatch skips all declared tests in the suite before name filtering. It is
not a pass; an entirely empty/excluded run still returns 2. Lua declarations
must compile and register valid suites on every platform. In particular,
`file_content(...)` in a declaration still reads its file. Selectors do not
hide syntax, helper, schema or quota errors.

Unknown suite/test properties are errors. Lua helpers and generated arrays are
supported, but test groups and executable module/file includes are not.
Excluded suites do not load/validate YAML, read a configuration fallback,
evaluate rules or call `verify`. Limits are listed [separately](isolation.md#limits).
