---
description: Revoke a Bifröst session, disconnect its SSH connections and run configured cleanup.
---

# `bifroest session dispose`

Revokes the selected session, closes all associated SSH connections and runs the normal environment and authorization disposal. The disposed session cannot be reused. Its stored metadata, audit logs and Recordings remain subject to their existing retention rules.

This revokes the session, not the user's login credentials. A new authorized login can create a new session.

!!! warning "Disposal can remove resources"
    Depending on the environment configuration, disposal can remove containers, Pods or managed accounts and their home directories. The command takes effect immediately, without a confirmation prompt. To close only current connections, use [`session disconnect`](disconnect.md).

## Syntax

<<cli_syntax("session dispose", "[flags] <id>", remote=True)>>

## Arguments

### `id` {: #argument-id }

Required session UUID from [`session ls`](ls.md), not an SSH connection or Recording ID. A missing session, an ID found in multiple flows, or the session executing this management command produces an error before disposal starts.

## Flags {: #session-dispose-flags }

Includes [general flags](../index.md#general-flags) supported in the selected invocation mode. Local `--configuration` is not available.

<<flag("format", "string", default="table", id_prefix="session-dispose-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`. A successful result contains `id`, `flow` and `action: dispose`.

## Examples

```shell
bifroest @bifroest-admin session dispose SESSION_UUID
ssh management@bifroest.example.org 'session dispose SESSION_UUID --format=json'
```

All authorized management users can dispose of sessions in any flow. No additional environment permission is required. The action is audited in the management flow and target flow according to their audit configuration.

Cleanup failure returns an error, not a success result. Connections are already closed and new connections to this session are rejected by the running service. Resource cleanup starts only after the disposed state has been persisted. Retry the command to finish incomplete cleanup; if persisting the session state itself failed, retry before restarting the service. Repeating disposal of a retained, already disposed session is safe.

## Availability

<<cli_availability(local=False, remote=True, direct_ssh=True)>>
