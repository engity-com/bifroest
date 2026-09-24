---
description: Verify and inspect a Bifröst session Recording artifact.
---

# `bifroest recording inspect`

Verifies a sealed native `.bcast` or CBOR `.becast` session Recording and writes one JSON object to standard output. Legacy `.cast`, `.cast.zst`, and binary `.becast` are also supported. Format detection uses the file magic, not the extension; the old and new `.becast` formats have different magic bytes. A failed verification produces no JSON output.

The input must be a regular, non-symlink file and must remain the same file with unchanged size, mode, and modification time throughout inspection. Standard input is deliberately unsupported.
When stdout is a regular file, it must not refer to the inspected Recording. A shell redirection using `>` can truncate a file before Bifröst starts and cannot be prevented by the command.

For native clear `.bcast`, `verificationScope` is `full`: the command verifies the signed envelope and reconstructs and verifies the complete Cast. Legacy `.cast` and `.cast.zst` also have `full` scope and include a `cast` object with event counts only, not session metadata or reasons. For encrypted native or legacy `.becast`, `verificationScope` is `outer`: only the signed envelope is checked, without decrypting the event content. `claimedStatus` and `claimedCastDigest` are signed outer-seal claims, **not** verified inner-Cast results; `status`, `castDigest`, and `cast` are omitted. Use `recording export` with a matching private identity for full verification. No event payloads are emitted by inspect.

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

The output schema is `bifroest.session-recording-inspection/v1`. `signature.valid` is always `true` in emitted output because invalid signatures fail before output is generated. `signature.trusted` is true only with a matching independently supplied producer ID. Native format values are `bcast/v1` and `becast-cbor/v1`; legacy values remain distinct. `castDigest` identifies fully verified signed Cast content only. Native containers report chunk count and claimed Cast size, but no ciphertext byte count or stream hash; those fields are reported only where the legacy format provides them.

## Example

Verify a Recording against an independently obtained producer ID:

```shell
bifroest recording inspect \
  --expectedProducerId 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  session.bcast
```
