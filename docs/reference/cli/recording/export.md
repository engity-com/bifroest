---
description: Verify and export a Bifröst session Recording as asciicast v3.
---

# `bifroest recording export`

Verifies a sealed native `.bcast` or CBOR `.becast` session Recording and exports its exact signed asciicast v3 stream. Legacy `.cast`, `.cast.zst`, and binary `.becast` remain readable. Format detection uses magic bytes rather than the file extension; old and new `.becast` have different magic. Compressed native chunks are reconstructed into a Cast, and encrypted `.becast` additionally requires a matching SSH private key.

The exported Cast contains captured terminal, standard-output, and standard-error content and can contain secrets displayed by programs. Protect the output according to its sensitivity.

`--with-sensitive` is mandatory before the input is opened for **every** format. The input must be a regular, non-symlink file and must remain the same file with unchanged size, mode, and modification time while Bifröst creates a private byte-exact snapshot. Verification and export use only that snapshot, preventing later input changes from altering the exported bytes. An encrypted snapshot remains encrypted; stdout export does not create a decrypted temporary file. Standard input is deliberately unsupported.

## Syntax

`bifroest recording export [flags] <file>`

## Arguments

`file` selects one sealed Recording artifact.

## Flags {: #recording-export-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("expectedProducerId", "string", id_prefix="recording-export-", heading=3)>>
External trust anchor containing exactly 64 hexadecimal characters. Obtain this value through an independently trusted channel. It is the lowercase hexadecimal SHA-256 digest of the RFC 4253 binary SSH public-key blob, which is the decoded Base64 field of the provisioned OpenSSH public-key line. A producer ID or public key embedded in the artifact is not a trust anchor.

Either this flag or `--allowUntrusted` is required.

<<flag("with-sensitive", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Explicitly authorizes access to sensitive recording content. Required even for clear recordings and even when exporting to a file.

<<flag("allowUntrusted", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Explicitly permits export after verifying only the artifact's cryptographic self-consistency. This does not establish who created the Recording and cannot be combined with `--expectedProducerId`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="recording-export-", heading=3)>>
Protected SSH private-key file used to decrypt encrypted `.becast`. Repeat the flag to provide multiple keys. Bifröst selects only the identity whose public-key fingerprint matches the signed recipient fingerprint. Ed25519 and RSA keys are supported. Clear `.bcast`, `.cast`, and `.cast.zst` inputs do not require this flag.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="recording-export-", heading=3)>>
Output file or `-` for standard output. The output parent directory must already exist. Standard output contains only Cast bytes; diagnostics and errors are written to standard error. Bifröst fully verifies native recordings (including decrypted event semantics) before emitting plaintext. Encrypted native input is preverified before opening an output file.

A named output is written through a private temporary file in the output directory and installed atomically. It cannot replace the input or a supplied decryption identity.

<<flag("force", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Atomically replaces an existing named output. This never permits replacing the Recording input or a supplied decryption identity.

## Examples

Export a trusted compressed Recording to a private Cast file:

```shell
bifroest recording export \
  --expectedProducerId 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --with-sensitive \
  --output session.cast \
  session.bcast
```

Decrypt a trusted BECast to standard output:

```shell
bifroest recording export \
  --expectedProducerId 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --with-sensitive \
  --decryptionIdentityFile ./recording-identity \
  session.becast
```

## External playback

Bifröst does not download remote artifacts or include a player. Obtain the byte-exact sealed artifact, inspect it with the same independent trust anchor, and export it to a protected file before playback. BECast additionally requires the externally retained private key matching its signed recipient fingerprint.

The resulting file is sensitive plaintext in asciicast v3 format. Use a player that supports asciicast v3 and unknown comment lines. See [Session recording](../../auditlog/recording.md#export-and-playback) for the complete operational workflow.
