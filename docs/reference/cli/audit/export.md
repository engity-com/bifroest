---
description: Verify and export a Bifröst audit journal.
---

# `bifroest audit export`

Verifies the signed committed journal state before writing JSON Lines in chain order. Bifröst can keep writing; later records are not included. The default view includes only `name`, optional `domain` and `outcome`, plus envelope metadata such as time and record ID. This applies to clear `.baudit` and encrypted `.beaudit`. Protect even redacted output. Export has bounded in-memory limits (including a 128 MiB output cap); use `audit verify` without materializing records for larger journals.

Use `--with-sensitive` to include confidential event fields. For `.beaudit`, this also requires the matching `--decryptionIdentityFile` and verifies the decrypted content. A redacted export of `.beaudit` needs no decryption identity. JSON Lines are an unsigned view, not a substitute for the original container.

## Syntax

`bifroest audit export [flags] [auditlogName]`

## Arguments

`auditlogName` selects one configured audit log by name and is required for local export. With `--source`, it is an optional output label, defaulting to `default`; use it for a non-default auditlog to preserve that name in exported JSONL. It is not a segment path. Remote sealed segments alone lack the signed head and cannot be exported with this command.

## Flags {: #audit-export-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-export-", heading=3)>>
Optional configuration to load. Without this flag, local export uses the same platform default as `bifroest run` and its configured signing key as producer trust. Cannot be combined with `--source`; offline export needs no configuration file.

<<flag("source", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Complete auditlog copy to read without a configuration file or signing private key, including the signed head and all segments. Requires `--expectedProducerId` from an independent trust source. A downloaded sealed segment alone is not a complete journal.

<<flag("encryptionPublicKeyFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Expected encryption recipient for `--source` when reading a redacted encrypted journal without a private key, or when supplying multiple decryption identities. For a sensitive export with one `--decryptionIdentityFile`, the recipient is derived from that identity instead. Not used with the configured local journal.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Private SSH key required together with `--with-sensitive` for encrypted event fields. Repeat the flag when needed. Without `--with-sensitive`, supplied decryption identities are not loaded or used for the redacted export.

<<flag("with-sensitive", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Explicitly include confidential event fields in the JSON Lines output. This does not make the output encrypted; protect the destination accordingly.

<<flag("expectedProducerId", "string", id_prefix="audit-export-", heading=3)>>
External trust anchor as a 64-hex producer ID. On the server, omit it to trust the configured signing key. With `--source`, it is required. Obtain the ID from the server's [`audit producer-id`](producer-id.md) command and retain it through an independently trusted channel. An ID copied from the journal is not a trust anchor.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-export-", heading=3)>>
Output file. `-` writes JSON Lines to stdout. The output file's immediate parent directory must already exist; the command does not create missing output directories. The parent is opened without following links where the platform supports it and remains pinned through the final safety check and atomic installation. Output paths inside any enabled configured journal or enabled recording repository, or aliasing a journal file, the loaded configuration file, a signing identity or a referenced encryption public-key file are rejected. Supplied decryption identities are also protected. When stdout is a regular file, the command rejects descriptors pointing to protected files, including journal heads and segments; normal pipes remain supported. Shell redirection with `>` can truncate a file before the command starts, so do not redirect stdout to protected files.

<<flag("force", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Replaces an existing output file.

## Examples

Export redacted JSON Lines on the Bifröst host using the default configuration and audit log:

```shell
bifroest audit export default
```

Export a complete offline journal with an independently obtained producer ID, without a configuration or signing private key:

```shell
bifroest audit export \
  --source /srv/audit-evidence/auditlog \
  --expectedProducerId "<trusted-64-hex-id>" \
  --output /srv/audit-evidence/redacted.jsonl
```
