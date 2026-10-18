---
description: Show redacted configuration settings for one Bifröst audit log.
---

# `bifroest audit show`

Shows the settings of one named audit log without exporting its events.

```shell
bifroest audit show default
```

## Syntax

<<cli_syntax("audit show", "[flags] <name>")>>

<<cli_syntax("audit show", "[flags] <name>", remote=True)>>

## Arguments

### `name` {: #argument-name }

`name` is the required configured auditlog name, as returned by [`audit ls`](ls.md).

## Flags {: #audit-show-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-show-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="audit-show-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

## Output

Redacted settings, including the auditlog name, enablement, Recording configuration and delivery targets. Declared target names and types remain visible; arbitrary strings such as paths, endpoints, credentials and templates are redacted. Audit-log settings remain redacted even when the management flow enables `includingCredentials` for `flow show`.

## Examples

### Check the selected Recording and delivery policy

1. Enable and configure [session recording](../../auditlog/recording.md#examples) on a named audit log.
2. Inspect that entry:

    ```shell
    bifroest audit show default --format=yaml
    ```

    Use the original configuration reference for the meaning of individual properties; redacted values cannot be recovered from this view.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Artifact-transfer permission is not required.
