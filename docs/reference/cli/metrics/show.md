---
description: Show all or selected operational metric families as a table, JSON or OpenMetrics.
---

# `bifroest metrics show`

Shows a live snapshot from the same data source as the monitoring listener's `/metrics` endpoint.

## Syntax

<<cli_syntax("metrics show", "[flags] [<metric>...]", remote=True)>>

With a standard SSH client, run `ssh management@bifroest.example.org 'metrics show'`.

## Arguments

### `metric` {: #argument-metric }

Optional exact metric family names from the [monitoring reference](../../monitoring.md#metrics). Omit them to show all currently available families. Multiple names select the union, including every label set. Repeated names do not duplicate output. Regex, label selectors and PromQL are not supported.

Select a histogram by its base family name, such as `bifroest_authentication_flow_evaluation_duration_seconds`, not by a `_bucket`, `_sum` or `_count` sample name. The complete histogram is returned.

An unknown name fails the command without metric output. A known family with no current measurements remains absent, including average ages when no objects are active; it is not filled with zero.

## Flags {: #metrics-show-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("format", "string", default="table", id_prefix="metrics-show-", heading=3)>>
Result format: `table`, `json` or `openmetrics`. Other commands' `yaml` and `cbor` formats are not supported here.

## Output

The default table contains sample names, values and labels. Histograms have bucket, sum and count rows. JSON contains `capturedAt`, `processStartedAt` and `families`; each family uses Prometheus protobuf JSON fields, preserving labels, types, histogram buckets and summary quantiles. Non-finite numbers are strings such as `"NaN"` or `"Infinity"`, and 64-bit integer fields are decimal strings. OpenMetrics includes HELP/TYPE metadata and one final `# EOF` line.

Every format includes the snapshot time and process start time; OpenMetrics carries them in a comment. Where process-start observation is unavailable, the startup timestamp is used. The snapshot is not a transaction across concurrent activity. Counters restart with the process; the command does not retain history or calculate rates.

## Examples

### Inspect connections without a monitoring port

1. Configure an authorized [management flow and workstation alias](../../../guides/management.md). A configured management flow enables metric collection even when `monitoring.enabled` is false.
2. Query two metric families:

    ```shell
    bifroest @bifroest-admin metrics show bifroest_connections_active bifroest_sessions_active
    ```

    The table includes all current label sets for those families.

3. Export the same selection for scripts:

    ```shell
    bifroest @bifroest-admin metrics show bifroest_connections_active bifroest_sessions_active --format=json
    ssh management@bifroest.example.org 'metrics show bifroest_connections_active --format=openmetrics'
    ```

## Availability

<<cli_availability(local=False, remote=True, direct_ssh=True)>>

Requires management access. Neither `includingCredentials` nor `allowArtifactTransfer` is required. Authorized-key and forced-command restrictions still apply.
