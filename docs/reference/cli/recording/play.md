---
description: Verify and replay captured Bifröst session output in the terminal.
---

# `bifroest recording play`

Verifies a Recording and replays its captured terminal output at the selected speed.

```shell
bifroest recording play --with-sensitive default RECORDING_UUID
```

## Syntax

<<cli_syntax("recording play", "[flags] <auditlogName> <recording-uuid>")>>

<<cli_syntax("recording play", "[flags] --expectedProducerId ID <file>")>>

<<cli_syntax("recording play", "[flags] <auditlogName> <recording-uuid>", remote=True)>>

## Arguments

### `auditlogName` {: #argument-auditlogName }

Configured auditlog name for repository selection. Used together with `recording-uuid`, locally or through `@target`.

### `recording-uuid` {: #argument-recording-uuid }

Recording UUID returned by [`recording ls`](ls.md) for the selected auditlog.

### `file` {: #argument-file }

One local `.bcast`, `.becast` or signed `.cast` file, as an alternative to repository selection. File inputs cannot be combined with `@target`.

## Flags {: #recording-play-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="recording-play-", heading=3)>>
Local repository configuration; defaults to the [platform path](../usage.md#configuration). Cannot be combined with a file input, `@target` or direct SSH.

<<flag("with-sensitive", "bool", default=False, id_prefix="recording-play-", heading=3)>>
Required before reading any Recording content. Playback is complete and never redacted.

<<flag("expectedProducerId", "string", id_prefix="recording-play-", heading=3)>>
Independently trusted 64-hex producer ID for copied or downloaded evidence. The client can use `X-ExpectedProducerId`. Configured local selection uses its signing identity instead; direct SSH does not accept this flag.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="recording-play-", heading=3)>>
Matching local private key for `.becast`; repeatable. The client can use `X-RecordingPrivateKey`. Keys stay on the CLI machine. Unavailable over direct SSH.

<<flag("allowUntrusted", "bool", default=False, id_prefix="recording-play-", heading=3)>>
Explicitly accept only cryptographic self-consistency for copied or downloaded content. Cannot be combined with an expected producer ID or configured local repository selection. See [producer trust](../verification.md#trust-a-producer).

<<flag("speed", "float", default=1, id_prefix="recording-play-", heading=3)>>
Playback-speed multiplier, greater than zero and at most `100`. `2` plays twice as fast. Available in all supported execution modes.

## Output

Replayed terminal content on stdout. The input is verified before playback begins. It is not an asciicast file; [`recording export`](export.md) writes that representation. `play` does not accept `--format`, `--output` or `--force`.

Remote playback requires `allowArtifactTransfer: true`. The integrated client verifies the downloaded original against the trusted producer and requested Recording ID before reading its content. Cancellation or an output failure stops playback with an error. See [protected destinations](../verification.md#protected-destinations).

## Examples

### Replay a session recorded on the host

1. Enable Recording and generate a session as described in [the recording guide](../../../guides/recording.md).
2. Find its ID:

    ```shell
    bifroest recording ls default
    ```

3. Replay the selected Recording at twice the original speed:

    ```shell
    bifroest recording play --with-sensitive --speed=2 default RECORDING_UUID
    ```

### Replay encrypted evidence on a workstation

Follow [the encrypted-evidence guide](../../../guides/evidence.md) to configure the server's public recipient key, independent producer trust and local private key. Then run:

```shell
bifroest @bifroest-admin recording play --with-sensitive evidence RECORDING_UUID
```

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Local invocation supports configured repositories and copied files. Direct SSH can play clear Recordings with `--with-sensitive` and the management flow's artifact-transfer permission. For encrypted content, the integrated client downloads and decrypts the original on the workstation.
