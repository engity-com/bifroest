---
description: Verify a configured, copied or downloaded Recording against a trusted producer without replaying content.
---

# `bifroest recording verify`

Verifies a Recording against trusted producer identity without exporting or replaying its Cast.

```shell
bifroest recording verify default RECORDING_UUID
```

## Syntax

<<cli_syntax("recording verify", "[flags] <auditlogName> <recording-uuid>")>>

<<cli_syntax("recording verify", "[flags] --expectedProducerId ID <file>")>>

<<cli_syntax("recording verify", "[flags] <auditlogName> <recording-uuid>", remote=True)>>

## Arguments

### `auditlogName` {: #argument-auditlogName }

Configured auditlog name for repository selection. Used together with `recording-uuid`, locally or through `@target`.

### `recording-uuid` {: #argument-recording-uuid }

Recording UUID returned by [`recording ls`](ls.md) for the selected auditlog.

### `file` {: #argument-file }

One local `.bcast`, `.becast` or signed `.cast` file, as an alternative to repository selection. File inputs need an independent expected producer ID and no local server configuration. They cannot be combined with `@target`.

## Flags {: #recording-verify-flags }

Includes [general executable flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="recording-verify-", heading=3)>>
Local repository configuration; defaults to the [platform path](../usage.md#configuration). Cannot be combined with a file input, `@target` or direct SSH.

<<flag("expectedProducerId", "string", id_prefix="recording-verify-", heading=3)>>
Independent 64-hex producer ID for copied or downloaded evidence. The client can use `X-ExpectedProducerId`. Configured local selection uses its signing identity and does not accept this flag. Unavailable over direct SSH.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="recording-verify-", heading=3)>>
Matching local SSH private key for full verification of encrypted `.becast`; repeatable. The client can use `X-RecordingPrivateKey`. Keys stay on the CLI machine. Without a supplied key, encrypted verification has outer scope; supplied non-matching keys fail. Unavailable over direct SSH.

<<flag("require-full", "bool", default=False, id_prefix="recording-verify-", heading=3)>>
Reject outer-only verification. Clear Recordings need no decryption key. Direct SSH cannot meet this requirement for encrypted content using a private key held on the workstation.

<<flag("format", "string", default="table", id_prefix="recording-verify-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

## Output

The default status is `verified (scope: outer)` or `verified (scope: full)`. Structured formats contain the verification result and scope. Success exits with status `0`; no Cast content is emitted.

Verification checks the trusted producer and, for remote selection, the requested Recording ID. Regular stdout files cannot replace the input, supplied private keys or protected configured state. See [Trust and verification](../verification.md).

## Examples

### Verify a Recording on its host

1. Generate a Recording and find its UUID using [the recording guide](../../../guides/recording.md).
2. Verify with the configured signing identity:

    ```shell
    bifroest recording verify default RECORDING_UUID --require-full
    ```

### Verify encrypted remote content locally

1. Configure the encrypted repository, trusted producer and recipient key as in [the workstation guide](../../../guides/evidence.md).
2. Require a full result:

    ```shell
    bifroest @bifroest-admin recording verify evidence RECORDING_UUID --require-full --format=json
    ```

    The matching private key is read on the workstation and never transmitted to the service.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Local invocation supports configured repositories and copied files. Remote-client verification downloads the original and requires `allowArtifactTransfer: true`, including outer-only verification.

Direct SSH accepts an auditlog name, Recording UUID, `--require-full` and `--format`. It verifies server-side evidence without artifact-transfer permission or access to a workstation's private decryption key.
