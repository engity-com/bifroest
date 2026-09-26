---
description: Verify a Bifröst session Recording against a trusted producer without exporting the Cast.
---

# `bifroest recording verify`

Verifies a sealed `.bcast` or `.becast` Recording against a trusted producer without outputting the Cast. Locally, an auditlog name and recording UUID select its configured Recording repository and signing identity. Offline verification takes a positional file and `--expectedProducerId ID`, with an ID obtained independently of the artifact. On success, the command reports `verified (scope: outer)` or `verified (scope: full)` on stdout and exits with status `0`.

When stdout is a regular file, the command refuses to write into its input or a supplied private key. Shell `>` redirection can truncate a file before Bifröst starts, so do not redirect verification output to protected files.

For clear `.bcast`, verification is full without a decryption key. For encrypted `.becast`, verification without `--decryptionIdentityFile` checks only the signed outer structure; it does not verify decrypted Cast content. Supply a matching private key for full verification. `--require-full` rejects outer-only results, including encrypted recordings without the key.

## Syntax

`bifroest recording verify [flags] <auditlogName> <recording-uuid>`

`bifroest recording verify [flags] --expectedProducerId ID <file.bcast|file.becast>`

## Arguments

`auditlogName` and `recording-uuid` select one sealed Recording in the configured repository. For an offline artifact, pass the copied or downloaded file instead.

## Flags {: #recording-verify-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="recording-verify-", heading=3)>>
Optional configuration for local name-and-UUID selection. Without it, Bifröst uses the platform default. Offline verification with `--expectedProducerId` needs no configuration.

<<flag("expectedProducerId", "string", id_prefix="recording-verify-", heading=3)>>
Independently obtained 64-hex producer ID for the input file. Obtain it from [`audit producer-id`](../audit/producer-id.md) on the Bifröst host through a trusted channel; an ID embedded in the file is not a trust anchor. Local UUID selection uses the signing identity from the configuration instead.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="recording-verify-", heading=3)>>
Matching private SSH key for full verification of encrypted `.becast` content. Without it, encrypted verification has outer scope only.

<<flag("require-full", "bool", default=False, id_prefix="recording-verify-", heading=3)>>
Require full verification. An encrypted `.becast` without a matching decryption identity fails instead of accepting outer-only verification.

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
