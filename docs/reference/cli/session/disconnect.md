---
description: Close the current SSH connections of a Bifröst session without revoking it.
---

# `bifroest session disconnect`

Closes all SSH connections currently associated with the selected session, including their channels and forwarding connections. The session remains valid and its environment and authorization are not disposed. New connections may reuse it under the normal session rules.

## Syntax

<<cli_syntax("session disconnect", "[flags] <id>", remote=True)>>

## Arguments

### `id` {: #argument-id }

Required session UUID from [`session ls`](ls.md), not an SSH connection or Recording ID. A missing session, an ID found in multiple flows, or the session executing this management command produces an error before any connections are closed.

## Flags {: #session-disconnect-flags }

Includes [general flags](../index.md#general-flags) supported in the selected invocation mode. Local `--configuration` is not available.

<<flag("format", "string", default="table", id_prefix="session-disconnect-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`. A successful result contains `id`, `flow` and `action: disconnect`.

## Examples

```shell
bifroest @bifroest-admin session disconnect SESSION_UUID
ssh management@bifroest.example.org 'session disconnect SESSION_UUID --format=json'
```

All authorized management users can disconnect sessions in any flow. No additional environment permission is required. The action is audited in the management flow and target flow according to their audit configuration. Disconnecting a session with no current connections succeeds without changing its lifecycle state.

To revoke a session and run its configured cleanup instead, use [`session dispose`](dispose.md).

## Availability

<<cli_availability(local=False, remote=True, direct_ssh=True)>>
