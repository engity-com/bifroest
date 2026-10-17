---
description: Verify a Bifröst session Recording against a trusted producer without exporting the Cast.
---

# `bifroest recording verify`

Verifies a sealed `.bcast` or `.becast` Recording against a trusted producer without outputting the Cast. Locally, an auditlog name and recording UUID select its configured Recording repository and signing identity. Offline verification takes a positional file and `--expectedProducerId ID`, with an ID obtained independently of the artifact. With a leading `@target`, the [management client](../management.md) downloads and verifies the selected original on the CLI machine. By default, a successful command reports `verified (scope: outer)` or `verified (scope: full)` on stdout and exits with status `0`; `--format` selects structured output instead.

When stdout is a regular file, the command refuses to write into its input or a supplied private key. Shell `>` redirection can truncate a file before Bifröst starts, so do not redirect verification output to protected files.

For clear `.bcast`, verification is full without a decryption key. For encrypted `.becast`, verification without `--decryptionIdentityFile` checks only the signed outer structure; it does not verify decrypted Cast content. Supply a matching private key for full verification. `--require-full` rejects outer-only results, including encrypted recordings without the key.

## Syntax

`bifroest recording verify [flags] <auditlogName> <recording-uuid>`

`bifroest recording verify [flags] --expectedProducerId ID <file.bcast|file.becast>`

`bifroest @target recording verify [flags] <auditlogName> <recording-uuid>`

## Arguments

`auditlogName` and `recording-uuid` select one sealed Recording in the configured repository. For an offline artifact, pass the copied or downloaded file instead.

## Flags {: #recording-verify-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="recording-verify-", heading=3)>>
Optional configuration for local name-and-UUID selection. Without it, Bifröst uses the platform default. Offline verification with `--expectedProducerId` needs no configuration. This flag cannot be combined with a remote target or an offline file input.

<<flag("expectedProducerId", "string", id_prefix="recording-verify-", heading=3)>>
Independently obtained 64-hex producer ID for the input file. Obtain it from [`audit producer-id`](../audit/producer-id.md) on the Bifröst host through a trusted channel; an ID embedded in the file is not a trust anchor. Remote selection requires this flag or a trusted `X-ExpectedProducerId` in the target's SSH configuration. Local UUID selection uses the signing identity from the configuration instead and does not accept this flag.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="recording-verify-", heading=3)>>
Matching private SSH key for full verification of encrypted `.becast` content. Repeat the flag to supply multiple keys. With `@target`, the key stays on the CLI machine; `X-RecordingPrivateKey` supplies its default path when the flag is omitted. If no key is supplied, encrypted verification has outer scope only; if none of the supplied keys matches the recipient, verification fails.

<<flag("require-full", "bool", default=False, id_prefix="recording-verify-", heading=3)>>
Require full verification. An encrypted `.becast` without a matching decryption identity fails instead of accepting outer-only verification.

<<flag("format", "string", default="table", id_prefix="recording-verify-", heading=3)>>
Output format: `table`, `json`, `yaml` or `cbor`. The default `table` format prints the status line shown above; structured formats contain the verification result and its scope.

## Examples

Verify a clear local Recording on the Bifröst host without exporting a Cast:

```shell
bifroest recording verify default <recording-uuid>
```

Verify an offline encrypted artifact and require full verification using the independently obtained producer ID and offline private key:

```shell
bifroest recording verify \
  --expectedProducerId "<trusted-64-hex-id>" \
  --decryptionIdentityFile /srv/audit-keys/recipient-key \
  --require-full \
  session.becast
```

Verify a remote Recording locally and emit a structured result:

```shell
bifroest @bifroest-admin recording verify \
  --expectedProducerId "<trusted-64-hex-id>" \
  --decryptionIdentityFile /srv/audit-keys/recipient-key \
  --require-full \
  --format=json \
  default <recording-uuid>
```

The management flow must enable `allowArtifactTransfer: true`, including for outer-only verification. The client checks the trusted producer and requested Recording ID; the decryption private key is never sent to the server.
