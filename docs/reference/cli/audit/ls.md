---
description: List configured audit logs and their journal, Recording and encryption settings.
---

# `bifroest audit ls`

Lists the audit logs in the selected configuration, including disabled and Recording-only entries.

```shell
bifroest audit ls
```

## Syntax

<<cli_syntax("audit ls")>>

<<cli_syntax("audit ls", remote=True)>>

## Arguments

None.

## Flags {: #audit-ls-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-ls-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="audit-ls-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

## Output

One row per auditlog name, ordered by name, indicating whether the audit journal, session recording and encryption are configured. This describes settings, not journal verification or delivery health. Use [`audit verify`](verify.md) to verify a journal.

## Examples

### Inspect separate workload and administration logs

1. Configure the two named entries in [the management guide](../../../guides/management.md).
2. Read their settings summary:

    ```shell
    bifroest @bifroest-admin audit ls --format=json
    ```

3. Select `workload` or `administration` with [`audit show`](show.md).

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Artifact-transfer permission is not required.
