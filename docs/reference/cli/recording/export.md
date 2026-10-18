---
description: Verify and export a Bifröst session Recording as signed asciicast v3.
---

# `bifroest recording export`

Verifies a Recording and exports its exact signed asciicast v3 stream.

```shell
bifroest recording export --with-sensitive --output session.cast default RECORDING_UUID
```

## Syntax

<<cli_syntax("recording export", "[flags] <auditlogName> <recording-uuid>")>>

<<cli_syntax("recording export", "[flags] --expectedProducerId ID <file>")>>

<<cli_syntax("recording export", "[flags] <auditlogName> <recording-uuid>", remote=True)>>

## Arguments

### `auditlogName` {: #argument-auditlogName }

Configured auditlog name for repository selection. Used together with `recording-uuid`, locally or through `@target`.

### `recording-uuid` {: #argument-recording-uuid }

Recording UUID returned by [`recording ls`](ls.md) for the selected auditlog.

### `file` {: #argument-file }

One local `.bcast`, `.becast` or signed `.cast` file, as an alternative to repository selection. Format detection uses file content, not its extension. Standard input is unsupported. File inputs cannot be combined with `@target`.

## Flags {: #recording-export-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("expectedProducerId", "string", id_prefix="recording-export-", heading=3)>>
Independently trusted 64-hex producer ID for copied or downloaded evidence. `X-ExpectedProducerId` provides the client's default. The local name-and-UUID selector uses its configured signing identity and does not accept this flag. Unavailable over direct SSH. See [producer trust](../verification.md#trust-a-producer).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="recording-export-", heading=3)>>
Local repository configuration; defaults to the [platform path](../usage.md#configuration). Cannot be combined with a file input, `@target` or direct SSH.

<<flag("with-sensitive", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Required before opening the input for every format and destination. Recording exports are complete and never redacted.

<<flag("allowUntrusted", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Explicitly accept cryptographic self-consistency without trusted producer identity. Cannot be combined with an expected producer ID or configured local repository selection. Unavailable over direct SSH.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="recording-export-", heading=3)>>
Local SSH private key for encrypted `.becast`; repeatable. Ed25519 and RSA identities are supported; the key must match the signed recipient fingerprint. `X-RecordingPrivateKey` provides the client's default. Keys stay on the CLI machine. Unavailable over direct SSH.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="recording-export-", heading=3)>>
Destination file or `-` for stdout. The immediate parent must already exist. Named output is published only after successful verification and [destination checks](../verification.md#protected-destinations). In `@target` mode, the file is on the CLI machine. Direct SSH writes stdout and does not accept this flag.

<<flag("force", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Replace an existing named output with the complete verified export. Protected inputs and key files remain protected. Unavailable over direct SSH.

## Output

The signed asciicast v3 stream, including captured terminal, stdout and stderr content. Encrypted `.becast` is decrypted and fully verified before plaintext is published. Clear `.bcast` and signed `.cast` need no decryption key. There is no `--format` selector.

The local input must be a regular, non-symlink file; changing it during export can cause the command to fail. The server does not automatically create plaintext Cast or JSONL copies.

## Examples

### Export a Recording from the local repository

1. Generate a Recording with [the recording guide](../../../guides/recording.md).
2. Find its UUID with [`recording ls`](ls.md).
3. Export to a separate path outside managed storage:

    ```shell
    bifroest recording export \
      --with-sensitive \
      --output session.cast \
      default RECORDING_UUID
    ```

### Export and independently inspect encrypted evidence

1. Configure encryption, producer pinning and local keys using [the workstation guide](../../../guides/evidence.md).
2. Download, verify and export the selected original:

    ```shell
    bifroest @bifroest-admin recording export \
      --with-sensitive \
      --output session.cast \
      evidence RECORDING_UUID
    ```

3. Independently inspect the exported Cast with the same trusted producer ID:

    ```shell
    bifroest recording inspect --expectedProducerId PRODUCER_ID session.cast
    ```

    `PRODUCER_ID` is the independently retained 64-hex value. The exported Cast's verified `castDigest` can be compared with the encrypted original's signed `claimedCastDigest`; see [`recording inspect`](inspect.md#output).

## External playback

Use an external player supporting asciicast v3 and unknown comment lines to play the exported file. The plaintext Cast is sensitive; its signature remains independently verifiable. Delivery targets retain sealed originals at `<producer-id>/<recording-uuid>.<suffix>`, which can also be copied for offline export with an independent producer ID.

<span id="built-in-playback"></span>

For playback directly in Bifröst, use the separate [`recording play`](play.md) command.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Local invocation supports configured repositories and copied files. Direct SSH can export clear Recordings to stdout with `--with-sensitive` and the management flow's artifact-transfer permission. For encrypted content, use the client with a local private key.
