---
description: Find commands for audit-log settings, event queries and signed journal processing.
---

# `bifroest audit` {: #audit-journals }

Inspect configured audit logs, query verified events, or verify and export signed journal evidence. Audit logging is configured separately under the root [`auditlog`](../../auditlog/index.md) list.

## Commands

| Command | Purpose |
| --- | --- |
| [`ls`](ls.md) | List configured audit logs and their enabled, Recording and encryption settings. |
| [`show`](show.md) | Show redacted settings of one audit log. |
| [`events`](events.md) | Query verified events with filters and a result limit. |
| [`producer-id`](producer-id.md) | Print the selected signing producer ID. |
| [`verify`](verify.md) | Verify a journal and report outer or full verification. |
| [`export`](export.md) | Verify and export JSON Lines. |
| [`merge`](merge.md) | Verify and chronologically merge multiple journals. |

Offline journal inputs are supported by `verify` and `export`. All evidence commands preserve the signed originals; see [Trust and verification](../verification.md).

## Examples

* [Configure basic or encrypted audit logging](../../auditlog/index.md#examples), then query it with [`audit events`](events.md#examples).
* [Manage a host remotely](../../../guides/management.md) with separate workload and administration audit logs.
* [Verify encrypted evidence on a workstation](../../../guides/evidence.md), keeping the recipient private key off the server.
