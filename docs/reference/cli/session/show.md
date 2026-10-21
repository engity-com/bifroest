---
description: Show metadata for one Bifröst session UUID.
---

# `bifroest session show`

Shows one session's metadata without applying the list command's default active-state filter.

```shell
bifroest session show SESSION_UUID
```

## Syntax

<<cli_syntax("session show", "[flags] <id>")>>

<<cli_syntax("session show", "[flags] <id>", remote=True)>>

## Arguments

### `id` {: #argument-id }

`id` is the required session UUID returned by [`session ls`](ls.md). A session ID is distinct from an SSH connection ID or Recording ID.

## Flags {: #session-show-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="session-show-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="session-show-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

## Output

Session ID, flow, lifecycle state, requesting user, remote endpoint and creation time, plus last-access and validity timestamps where available. A missing session or an ID found in multiple flows produces an error.

## Examples

### Inspect a session found in a listing

1. Find the session:

    ```shell
    bifroest @bifroest-admin session ls --flow=local --state=all
    ```

2. Replace `SESSION_UUID` with a returned ID:

    ```shell
    bifroest @bifroest-admin session show SESSION_UUID --format=yaml
    ```

    A session may disappear between the two calls if it is removed by normal cleanup.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Local inspection supports filesystem session storage; management queries the running repository.
