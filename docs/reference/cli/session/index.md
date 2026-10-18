---
description: List Bifröst sessions and inspect session metadata locally or remotely.
---

# `bifroest session`

Inspect session metadata: identity, requesting user, flow, lifecycle state and timestamps. A Bifröst session can be reused by multiple SSH connections; this listing is not a process or network-connection list.

## Commands

| Command | Purpose |
| --- | --- |
| [`ls`](ls.md) | List sessions, with flow, user and state filters. |
| [`show`](show.md) | Show one session selected by UUID. |

Local inspection reads configured filesystem session storage. Remote queries use the running service's session repository. See [session configuration](../../session/index.md) for storage and reuse behavior.

## Examples

[Manage a Bifröst host remotely](../../../guides/management.md) sets up a local-account flow and a separate administration connection, then uses `session ls` to find the workload session.
