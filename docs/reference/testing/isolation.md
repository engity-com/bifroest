---
description: Understand the offline test capability boundary, admitted Lua and Go templates, and enforced resource limits.
---

# Isolation and limits

Tests use the selected YAML configuration and the facts you supply. Lua can
read additional fixture data only through `file_content`. Each case starts
with fresh Lua state, so variables changed by a previous
case do not affect it. Bifröst includes GoLua v0.4.1 (Lua 5.5); you do not need
an external Lua installation. Builds without quota support refuse to run tests.

!!! warning "Not a hard OS sandbox"
    Interpreter accounting/cooperative time limits do not impose hard process
    RSS/CPU bounds or protect against interpreter defects and hostile concurrent
    filesystem changes. Use an outer OS/container boundary when needed.

## Lua capabilities {: #lua }

The [Lua API](lua.md) provides `suite`, `object`, `list`, `null`, `file_content` and the
allowlisted base functions `assert`, `error`, `type`, `tostring`, `tonumber`,
`pairs`, `ipairs`, `next`, `select`, `pcall`.

There is no `os`, `io`, `package`, `require`, `load`, `dofile`, debug/Go bridge,
raw access, metatable manipulation, random/clock library or `print`. Immutable
views cannot be modified with raw setters/reflection. `file_content` captures
data, not executable Lua includes. See [file input rules](lua.md#function-file-content).

`pcall` shares the outer budget, not a replenished child quota. Caught/ignored
helper or assertion errors remain errors/failures; quotas cannot become success
through exception handling.

## Resource bounds {: #limits }

| Resource | Limit |
| --- | --- |
| Each discovery/replay, including compilation/verification | 2,000,000 VM CPU units, 16-MiB allocation-accounting budget, 500-ms runtime quota. |
| Each source/configuration/helper file | 64 KiB. |
| Captured `file_content` inputs per suite | 64 paths, 4 MiB total. |
| Discovery | 100,000 inputs/directory entries, including ignored entries; 256 nested levels. |
| Include/exclude filters | At most 64 expressions per group, 4 KiB each. |
| Suite/configuration | 64 tests, 32 flows. |
| Test data/assertions | 128 assertions per test; 2,048 fixture nodes; depth 16; 4-KiB data strings. |
| Platform selector | 64 strings per field, 256 bytes each; OS/architecture identifiers at most 32 lowercase letters/digits, `_`/`-`. |
| Admitted policy template | 4-KiB source, 128 AST nodes, depth 16. |
| Local target normalization | 64 KiB, 2,048 nodes, depth 16, 4-KiB strings, retaining integer types. |

Exceeding a bound is an error, not silent truncation or a skip. Comparison output
is bounded; arbitrary runtime/provider errors and YAML content are not dumped.
Assertion values/reasons can still appear in reports: use synthetic data.

## Policy templates {: #templates }

Lua quotas do not bound arbitrary Go template functions. Offline admission
therefore permits only text, fields/literals, `if`/`else` and
`eq/ne/lt/le/gt/ge/and/or/not/len`. Loops, named/recursive templates,
variable/chain constructs and all other functions, including allocating Sprig
helpers and host readers, are rejected.

Admitted expressions still use the [production renderer](../templating/index.md),
not a separate policy implementation. [Local mapping](local.md#authentication)
and [OIDC snapshots](oidc.md) describe additional field/method boundaries.

## Configuration admission

YAML aliases/merges are rejected before normal product decoding. Windows local
environments require explicit host-dependent shell selectors before defaults
can enter the controlled projection. Product packages may initialize globals
at process startup, but they are not used for these selectors. Other defaults,
references and validation remain production behavior.

## Container execution

The normal Bifröst image accepts the same `test` command. The container runtime
starts it; Lua cannot create containers. Prepare a locally available image and
existing absolute host directories first. Replace paths, `LOCAL_IMAGE_ID` and
UID/GID with your local values. Mount the test directory and the same configuration
file you intend to use for Bifröst, both read-only. The report directory must be
writable by that user:

```shell
docker run --rm --pull=never --network=none --read-only --user 1000:1000 --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=64 --memory=256m --cpus=1 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m --mount type=bind,src=/absolute/project/tests,dst=/workspace/tests,readonly --mount type=bind,src=/absolute/project/configuration.yaml,dst=/workspace/configuration.yaml,readonly --mount type=bind,src=/absolute/reports,dst=/reports --workdir=/workspace LOCAL_IMAGE_ID test tests --configuration configuration.yaml --json /reports/testing.json --junit /reports/testing.xml
```

Inputs and the root filesystem are read-only; only reports and bounded temporary
storage are writable. No network, published ports or host sockets are needed.
These outer limits do not replace the Lua limits above. Linux container results
do not establish native Windows/macOS behavior.
