---
description: Inspect one Bifröst flow's redacted configuration settings.
---

# `bifroest flow show`

Shows the settings of one configured flow.

```shell
bifroest flow show local
```

## Syntax

<<cli_syntax("flow show", "[flags] <name>")>>

<<cli_syntax("flow show", "[flags] <name>", remote=True)>>

## Arguments

### `name` {: #argument-name }

`name` is the required flow name, as returned by [`flow ls`](ls.md).

## Flags {: #flow-show-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="flow-show-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="flow-show-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

## Output

Key/value settings by default, or a structured settings object. Arbitrary strings are redacted, including image references, Kubernetes name templates, commands, environment variables and SSH certificate extension values. Structural flow/auditlog names, authorization/environment types, non-string settings and fixed image-pull policies remain visible.

Local inspection always uses this redacted view. A management flow can explicitly enable [`includingCredentials`](../../environment/management.md#property-includingCredentials) for its own `flow show` output. That server setting is not a client flag and does not affect audit-log detail redaction. A missing flow produces an error.

## Examples

### Check how an administration connection is routed

1. Configure the two distinct flows in [the management guide](../../../guides/management.md).
2. Inspect the administration flow:

    ```shell
    bifroest @bifroest-admin flow show administration --format=yaml
    ```

    The output identifies the management environment and selected administration audit log. Redacted values do not mean that the corresponding setting is absent.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

The selected local configuration or remote service must contain the named flow.
