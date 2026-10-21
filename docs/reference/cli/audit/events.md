---
description: Query verified Bifröst audit events with name, flow, time and result-limit filters.
---

# `bifroest audit events`

Shows the newest matching audit events after verifying the journal's captured signed committed state.

```shell
bifroest audit events default --limit=20
```

## Syntax

<<cli_syntax("audit events", "[flags] <name>")>>

<<cli_syntax("audit events", "[flags] <name>", remote=True)>>

## Arguments

### `name` {: #argument-name }

`name` is the required configured auditlog name. This command queries repositories; it does not accept an offline `--source` directory. Use [`audit export`](export.md) for a copied journal.

## Flags {: #audit-events-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-events-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="audit-events-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

<<flag("name", "string", id_prefix="audit-events-", heading=3)>>
Exact event-name filter. See the [event reference](../../auditlog/events.md).

<<flag("flow", "string", id_prefix="audit-events-", heading=3)>>
Exact flow-name filter; requires `--with-sensitive` because the flow is confidential event data.

<<flag("since", "Timestamp", "../../data-type.md", id_prefix="audit-events-", heading=3)>>
Inclusive start time in RFC 3339 format, for example `2026-01-02T12:00:00Z`.

<<flag("until", "Timestamp", "../../data-type.md", id_prefix="audit-events-", heading=3)>>
Inclusive end time in RFC 3339 format.

<<flag("limit", "uint", default=100, id_prefix="audit-events-", heading=3)>>
Number of newest matches to return. `0` selects all matches, subject to the result limits below. Name, flow and time filters are applied before this selection.

<<flag("with-sensitive", "bool", default=False, id_prefix="audit-events-", heading=3)>>
Include confidential fields. Encrypted journals need a matching local decryption key for this view.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-events-", heading=3)>>
Local private-key file for encrypted private fields; repeatable. Available locally and through `@target`, not direct SSH. Remote keys are only accepted with `--with-sensitive`; `X-AuditPrivateKey` supplies the client default.

<<flag("expectedProducerId", "string", id_prefix="audit-events-", heading=3)>>
Independently trusted producer ID for sensitive `@target` queries. Requires `--with-sensitive`; alternatively provision `X-ExpectedProducerId` in the SSH configuration. Local queries use the configured signing identity.

## Output

The default table shows time, event name, domain, outcome and record ID, plus flow when sensitive output is requested. Structured output contains events with their timestamps and origin metadata. Results preserve journal order within the selected newest matches.

Journal verification includes events excluded by the filters. A selection is limited to **250,000 events** and **64 MiB** of event data. Exceeding a limit fails the command; narrow the filters or lower `--limit` in that case. `--limit=0` does not disable these bounds.

## Examples

### Query events after enabling an audit log

1. Configure and use [basic audit logging](../../auditlog/index.md#basic-audit-logs).
2. Query public events from that configured journal:

    ```shell
    bifroest audit events default --limit=20 --format=json
    ```

3. Narrow the query to a recorded event name and time window:

    ```shell
    bifroest audit events default \
      --name=connection.closed \
      --since=2026-01-02T12:00:00Z \
      --until=2026-01-02T13:00:00Z \
      --limit=50
    ```

    Choose times that cover the generated events. For encrypted, sensitive remote queries, follow [the workstation verification guide](../../../guides/evidence.md).

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Public remote queries need no artifact-transfer permission. Sensitive queries require `allowArtifactTransfer: true`; the integrated client downloads and verifies the journal locally. Direct SSH can read clear private fields but cannot use a workstation's decryption key.
