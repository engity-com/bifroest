---
description: List configured Bifröst flows locally or through a management connection.
---

# `bifroest flow ls`

Lists configured flows in ascending name order.

```shell
bifroest flow ls
```

## Syntax

<<cli_syntax("flow ls")>>

<<cli_syntax("flow ls", remote=True)>>

## Arguments

None.

## Flags {: #flow-ls-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="flow-ls-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="flow-ls-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

## Output

One row per flow, with its name, selected auditlog, authorization type and environment type. This is a configuration listing, not a count of active sessions.

## Examples

### Inspect the configured flows remotely

1. Use the server configuration and SSH alias from [the management guide](../../../guides/management.md).
2. List the `administration` and `local` flows:

    ```shell
    bifroest @bifroest-admin flow ls --format=json
    ```

3. Select a returned name with [`flow show`](show.md).

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Local use reads a configuration file; remote use reads the service's loaded configuration. See [Invocation and data sources](../usage.md).
