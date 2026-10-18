---
description: Show verified repository metadata for one sealed Bifröst Recording.
---

# `bifroest recording show`

Shows verified metadata for one sealed Recording selected by auditlog name and UUID.

```shell
bifroest recording show default RECORDING_UUID
```

## Syntax

<<cli_syntax("recording show", "[flags] <auditlogName> <id>")>>

<<cli_syntax("recording show", "[flags] <auditlogName> <id>", remote=True)>>

## Arguments

### `auditlogName` {: #argument-auditlogName }

Required configured auditlog name with Recording enabled.

### `id` {: #argument-id }

Required Recording UUID, as returned by [`recording ls`](ls.md).

## Flags {: #recording-show-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="recording-show-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="recording-show-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

## Output

Details include Recording ID, auditlog, producer ID, format, status, timestamps, encryption state, verification scope, container size and chunk count. Encrypted Recordings expose signed outer metadata; status and other outer-seal claims do not replace full inner-Cast verification. This command does not accept a decryption identity; use [`recording verify`](verify.md) for full verification.

A missing artifact, invalid signature or ID mismatch produces an error instead of metadata.

## Examples

### Inspect a Recording found remotely

1. List a repository through the [configured management alias](../../../guides/management.md):

    ```shell
    bifroest @bifroest-admin recording ls workload
    ```

2. Replace `RECORDING_UUID` with a returned ID:

    ```shell
    bifroest @bifroest-admin recording show workload RECORDING_UUID --format=yaml
    ```

    This reads metadata without downloading the Recording to the workstation.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Metadata access needs no artifact-transfer permission. For a copied file, use [`recording inspect`](inspect.md).
