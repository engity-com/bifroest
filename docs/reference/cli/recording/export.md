---
description: Verify and export a Bifröst session Recording as asciicast v3.
---

# `bifroest recording export`

Verifies a sealed `.bcast` or `.becast` session Recording and exports its exact signed asciicast v3 stream. Locally, select a configured auditlog name and a recording UUID; offline, supply the artifact path and an independently trusted producer ID. With a leading `@target`, the [management client](../management.md) downloads the selected signed original and verifies and exports it on the CLI machine. A standalone signed `.cast` is also accepted for verified copying. Format detection uses the content, not the file extension; unsupported formats fail closed. Compressed native chunks are reconstructed into a Cast, and encrypted `.becast` additionally requires a matching SSH private key.

The exported Cast contains captured terminal, standard-output, and standard-error content and can contain secrets displayed by programs. It is **never redacted**, unlike redacted-by-default audit JSONL exports. Protect the output according to its sensitivity; even the original encrypted container exposes public metadata. Bifröst does not automatically create plaintext `.cast` or `.jsonl` files.

`--with-sensitive` is mandatory before the input is opened for **every** format. The input must be a regular, non-symlink file and must remain the same file with unchanged size, mode, and modification time while Bifröst creates a private byte-exact snapshot. Verification and export use only that snapshot, preventing later input changes from altering the exported bytes. An encrypted snapshot remains encrypted; stdout export does not create a decrypted temporary file. Standard input is deliberately unsupported. Local UUID selection uses the platform's default configuration; offline export with `--expectedProducerId` needs no configuration.

## Syntax

`bifroest recording export [flags] <auditlogName> <recording-uuid>`

`bifroest recording export [flags] --expectedProducerId ID <file.bcast|file.becast>`

`bifroest @target recording export [flags] <auditlogName> <recording-uuid>`

## Arguments

`auditlogName` and `recording-uuid` select a sealed Recording from the configured repository, on the server when using `@target`. For offline export, pass the copied or downloaded artifact as a positional file instead. Output paths and decryption identities refer to the CLI machine.

## Flags {: #recording-export-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("expectedProducerId", "string", id_prefix="recording-export-", heading=3)>>
External trust anchor containing exactly 64 hexadecimal characters. Obtain this value through an independently trusted channel. It is the lowercase hexadecimal SHA-256 digest of the RFC 4253 binary SSH public-key blob, which is the decoded Base64 field of the provisioned OpenSSH public-key line. A producer ID or public key embedded in the artifact is not a trust anchor.

Use this flag for copied or downloaded artifacts. Remote selection requires it or an independently provisioned `X-ExpectedProducerId` in the target's SSH configuration, unless explicitly using `--allowUntrusted`. The local name-and-UUID form uses the configured signing identity and does not accept `--expectedProducerId`. `--expectedProducerId` and `--allowUntrusted` are mutually exclusive.

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="recording-export-", heading=3)>>
Optional configuration for local name-and-UUID selection; when omitted, Bifröst loads the platform's default configuration for local selection. Offline export with an expected producer ID needs no configuration. This flag cannot be combined with a remote target or an offline file input.

<<flag("with-sensitive", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Explicitly authorizes access to sensitive recording content. Required even for clear recordings and even when exporting to a file.

<<flag("allowUntrusted", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Explicitly permits export after verifying only the artifact's cryptographic self-consistency. This does not establish who created the Recording and cannot be combined with `--expectedProducerId`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="recording-export-", heading=3)>>
Protected SSH private-key file used to decrypt encrypted `.becast`. Repeat the flag to provide multiple keys. Bifröst selects only the identity whose public-key fingerprint matches the signed recipient fingerprint. Ed25519 and RSA keys are supported. Clear `.bcast` and signed `.cast` inputs do not require this flag. With `@target`, the private key stays on the CLI machine; `X-RecordingPrivateKey` in SSH configuration provides its default path when this flag is omitted.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="recording-export-", heading=3)>>
Output file or `-` for standard output. The output parent directory must already exist. Standard output contains only Cast bytes; diagnostics and errors are written to standard error. Bifröst fully verifies native recordings (including decrypted event semantics) before emitting plaintext. Encrypted native input is preverified before opening an output file.

A named output is written through a private temporary file in the output directory and installed atomically. It cannot replace the input or a supplied decryption identity.

<<flag("force", "bool", default=False, id_prefix="recording-export-", heading=3)>>
Atomically replaces an existing named output. This never permits replacing the Recording input or a supplied decryption identity.

## Examples

On the Bifröst host, export a clear local Recording by UUID without repeating the signing producer ID or configuration path:

```shell
bifroest recording export \
  --with-sensitive \
  --output session.cast \
  default <recording-uuid>
```

Run this from a directory outside the configured journal and Recording repository. If the input is encrypted `.becast`, keep its private decryption key on a separate verification workstation instead of putting it on the Bifröst server; use the offline or management-client workflow below.

Export a trusted clear `.bcast` to a private Cast file without a decryption key:

```shell
bifroest recording export \
  --expectedProducerId "<producer-id>" \
  --with-sensitive \
  --output session.cast \
  session.bcast
```

Decrypt and fully verify a trusted `.becast` using the offline age SSH private identity, then independently verify the exported Cast:

```shell
bifroest recording export \
  --with-sensitive \
  --expectedProducerId "<producer-id>" \
  --decryptionIdentityFile /secure/offline/recording-identity \
  --output session.cast \
  session.becast
bifroest recording inspect --expectedProducerId "<producer-id>" session.cast
```

Replace `<producer-id>` with the independently provisioned 64-hex value; it is a placeholder, not a working trust anchor. The decryption identity is distinct from the audit signing key and stays on the verification workstation. To verify the encrypted original without exporting a Cast, use [`recording verify`](verify.md) with the same trusted ID, private identity and `--require-full`. Before export, `inspect` on the encrypted original reports only `verificationScope: "outer"` and `claimedCastDigest`. After successful export, `inspect` on `session.cast` reports `verificationScope: "full"` and a verified `castDigest`; compare the two digests. The encrypted export fully verifies the inner Cast against the signed seal before publishing plaintext. Clear `.bcast` likewise produces a fully verified Cast, without a decryption identity.

Export an encrypted Recording through the management client, keeping both the decryption key and plaintext output on the CLI machine:

```shell
bifroest @bifroest-admin recording export \
  --with-sensitive \
  --expectedProducerId "<producer-id>" \
  --decryptionIdentityFile /secure/offline/recording-identity \
  --output session.cast \
  default <recording-uuid>
```

The authorized management flow must enable `allowArtifactTransfer: true`. SSH authentication and host-key checking are described in [Management commands](../management.md#ssh-client-and-trust). The downloaded original is verified against both the trusted producer and the requested Recording ID before its content is exported.

## Built-in playback

`recording play` verifies the selected artifact and replays its captured terminal output to standard output. It accepts the same local name-and-UUID, offline file, and remote selectors as export, and requires `--with-sensitive`. Use `--speed` to change playback speed; its default is `1` and its valid range is greater than zero through `100`.

```shell
bifroest recording play --with-sensitive default <recording-uuid>
bifroest recording play --with-sensitive --expectedProducerId "<producer-id>" session.bcast
bifroest @bifroest-admin recording play \
  --with-sensitive \
  --expectedProducerId "<producer-id>" \
  --decryptionIdentityFile /secure/offline/recording-identity \
  --speed=2 \
  default <recording-uuid>
```

Encrypted playback needs the matching local private key, just like export. Remote playback also requires `allowArtifactTransfer: true`; it downloads and verifies the original on the CLI machine. `--output` and `--force` belong to export and are not accepted by `play`.

## External playback

For an external player, first export the verified Recording to a protected Cast file using one of the workflows above. You can also copy the byte-exact sealed artifact from `recording.directory/sealed/<recording-uuid>.<suffix>` or download the remote delivery target's `<producer-id>/<recording-uuid>.<suffix>` object for offline verification and export. BECast additionally requires the externally retained private key matching its signed recipient fingerprint.

The resulting file is sensitive plaintext in asciicast v3 format. Use a player that supports asciicast v3 and unknown comment lines. See [Session recording](../../auditlog/recording.md#export-and-playback) for the complete operational workflow and the [native recording vectors](../../../formats/recording-vectors.md) for test artifacts. For native `.bcast` and CBOR `.becast`, the [canonical byte-level representation](../../../formats/cast.md#canonical-standalone-cast) and signature are bound by the native container. Every exported signed Cast can be verified independently against the same producer ID.
