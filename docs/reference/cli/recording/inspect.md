---
description: Verify and inspect a Bifröst session Recording artifact.
---

# `bifroest recording inspect`

Verifies a sealed `.cast`, `.cast.zst`, or `.becast` session Recording and writes one JSON object to standard output. For clear formats, the command verifies the Cast digest, embedded signing key, signature, completion status, and container-specific hashes and sizes before producing output. A failed verification produces no JSON output.

The input must be a regular, non-symlink file and must remain the same file with unchanged size, mode, and modification time throughout inspection. Standard input is deliberately unsupported.

For `.cast` and `.cast.zst`, `verificationScope` is `full`, and the `cast` object contains signed session metadata, completion details, and event counts. Event payloads are never emitted. For encrypted `.becast`, `verificationScope` is `outer`: the command verifies the signed container structure and ciphertext hashes without requesting a decryption key or exposing its inner Cast metadata. Its status and Cast digest are signed claims from the outer seal; verifying them against the encrypted Cast requires explicit decryption outside this command. The `encrypted` and `compressed` properties state the transformations used by each format.

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

The output schema is `bifroest.session-recording-inspection/v1`. `signature.valid` is always `true` in emitted output because invalid signatures fail before output is generated. `castDigest` identifies the uncompressed signed Cast content. Container formats additionally report their chunk counts, encoded byte counts, and stream hash.

## Example

Verify a Recording against an independently obtained producer ID:

```shell
bifroest recording inspect \
  --expectedProducerId 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  session.cast.zst
```
