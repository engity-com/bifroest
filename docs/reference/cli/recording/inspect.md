---
description: Verify and inspect a Bifröst session Recording artifact.
---

# `bifroest recording inspect`

Verifies a sealed `.bcast` or `.becast` session Recording and writes one JSON object to standard output. It also accepts a signed `.cast` export for independent verification. Format detection uses the file content, not the extension; unsupported formats fail closed. A failed verification produces no JSON output.

The input must be a regular, non-symlink file and must remain the same file with unchanged size, mode, and modification time throughout inspection. Standard input is deliberately unsupported.
When stdout is a regular file, it must not refer to the inspected Recording. A shell redirection using `>` can truncate a file before Bifröst starts and cannot be prevented by the command.

For clear `.bcast`, `verificationScope` is `full`: the command verifies the signed envelope and reconstructs and verifies the complete Cast without a private key. A signed `.cast` also has `full` scope and includes a `cast` object with event counts only, not session metadata or reasons. For encrypted `.becast`, `verificationScope` is `outer`: only the signed envelope is checked, without a decryption key or decrypted event content. `claimedStatus` and `claimedCastDigest` are signed outer-seal claims, **not** verified inner-Cast results; `status`, `castDigest`, and `cast` are omitted. Use [`recording export`](export.md) with a matching private identity for full verification, then inspect the exported `.cast` independently and compare its fully verified `castDigest` with the original `claimedCastDigest`. No event payloads are emitted by inspect, but its public metadata still needs protection.

## Syntax

`bifroest recording inspect [flags] <file>`

## Arguments

`file` selects one sealed Recording artifact. Format detection uses the artifact content rather than its file-name extension.

## Flags {: #recording-inspect-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("expectedProducerId", "string", id_prefix="recording-inspect-", heading=3)>>
External trust anchor containing exactly 64 hexadecimal characters. Obtain this value through an independently trusted channel; the producer ID or public key embedded in the inspected artifact is not a trust anchor.

When this flag is present, a producer mismatch fails inspection and `signature.trusted` is `true` on success. Without it, the command verifies only cryptographic self-consistency and reports `signature.trusted` as `false`.

## Output

The output schema is `bifroest.session-recording-inspection/v1`. `signature.valid` is always `true` in emitted output because invalid signatures fail before output is generated. `signature.trusted` is true only with a matching independently supplied producer ID. Format values are `bcast/v1`, `becast-cbor/v1`, and `cast/v3` for standalone signed exports. `castDigest` identifies fully verified signed Cast content only; native containers also report chunk count and claimed Cast size.

## Example

Verify a copied sealed encrypted Recording against an independently obtained producer ID, without a decryption key:

```shell
bifroest recording inspect \
  --expectedProducerId "<producer-id>" \
  session.becast
```

Replace `<producer-id>` with the independently provisioned 64-hex value; it is a placeholder, not a working trust anchor. An encrypted result has `verificationScope: "outer"`, not a verified inner status or digest. After [full export](export.md#examples), inspect `session.cast` with the same flag: that independent inspection has `verificationScope: "full"` and a verified `castDigest`. For `.bcast`, inspecting the sealed original already gives a fully verified `castDigest`. See the [operational workflow](../../auditlog/recording.md#export-and-playback), [recording format](../../../formats/recording.md#recording-identity-and-chain), and [native vectors](../../../formats/recording-vectors.md).
