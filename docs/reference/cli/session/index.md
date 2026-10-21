---
description: Inspect Bifröst sessions and remotely disconnect or dispose of them.
---

# `bifroest session`

Inspect session metadata: identity, requesting user, flow, lifecycle state and timestamps. A Bifröst session can be reused by multiple SSH connections; this listing is not a process or network-connection list.

## Commands

| Command | Purpose |
| --- | --- |
| [`ls`](ls.md) | List sessions, with flow, user and state filters. |
| [`show`](show.md) | Show one session selected by UUID. |
| [`disconnect`](disconnect.md) | Close a session's current SSH connections without revoking it. |
| [`dispose`](dispose.md) | Revoke and disconnect a session, then run its configured cleanup. |

Local inspection reads configured filesystem session storage. Remote queries use the running service's session repository. See [session configuration](../../session/index.md) for storage and reuse behavior.

Session control is available only through `@target` or direct management SSH. All authorized management users can operate on sessions in any flow; neither `includingCredentials` nor `allowArtifactTransfer` is required. A command cannot target its own executing management session.

## Examples

[Manage a Bifröst host remotely](../../../guides/management.md) sets up a local-account flow and a separate administration connection, then uses `session ls` to find the workload session.
