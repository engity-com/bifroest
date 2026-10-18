---
description: List and filter Bifröst session metadata.
---

# `bifroest session ls`

Lists authorized, non-expired sessions by default.

```shell
bifroest session ls
```

## Syntax

<<cli_syntax("session ls")>>

<<cli_syntax("session ls", remote=True)>>

## Arguments

None.

## Flags {: #session-ls-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="session-ls-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="session-ls-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

<<flag("flow", "string", id_prefix="session-ls-", heading=3)>>
Select sessions whose flow name matches exactly.

<<flag("user", "string", id_prefix="session-ls-", heading=3)>>
Select sessions whose requesting user matches exactly.

<<flag("state", "string", default="active", id_prefix="session-ls-", heading=3)>>
`active` selects `authorized` sessions whose validity has not expired. `new`, `authorized` and `disposed` match that lifecycle state directly; `authorized` can therefore include expired sessions. `all` disables state filtering. Retained state depends on the repository's lifecycle and cleanup.

## Output

Rows contain session ID, flow, state, requesting user and creation time, ordered by creation time and then ID. Structured results additionally contain available remote, last-access and validity metadata. Repository inspection can report unreadable entries on stderr.

## Examples

### Find a user's sessions in one flow

1. Configure and use the `local` flow from [the management guide](../../../guides/management.md).
2. From the administrator's workstation, query that flow:

    ```shell
    bifroest @bifroest-admin session ls --flow=local --user=alice --state=all --format=json
    ```

    Replace `alice` with the requesting SSH username. `--flow=local` excludes the separate administration session.
3. Use a returned ID with [`session show`](show.md).

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Local inspection supports filesystem session storage; management queries the running repository.
