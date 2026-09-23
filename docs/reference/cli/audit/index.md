---
description: Verify, decrypt, export, and merge Bifröst audit journals.
---

# `bifroest audit` {: #audit-journals }

Audit commands never create or replace identities and do not alter journal evidence files. By default, they load each selected configured signing identity without creating a missing key and use its producer ID as the trust anchor. Every signing or decryption private-key file loaded by these commands must be a regular, non-symlink file with exactly one hard link and a size of at most 1 MiB. On Unix it must be owned by the effective process user and must not be accessible by group or others. On Windows it must be owned by the current process-token owner and have a protected DACL whose allow entries name only that owner, `OWNER RIGHTS`, or `SYSTEM`.

For least-privilege offline verification, `--expectedProducerId <auditlogName>=<producer-id>` supplies an external trust anchor for one selected source. The producer ID is the 64-hex-character SHA-256 identity of the signing public key. Record it through an independently trusted provisioning channel; do not take it from the journal currently being verified. Repeat the flag for multiple selected sources. When a source has an explicit expected producer ID, its configured signing private key is not opened and may be absent. Without this flag, the configured private key remains mandatory, so there is no trust-anchor-less mode.

Stop the Bifröst service before running these commands so the journal remains stable throughout verification.

Run them on quiescent storage whose journal and output parent directories are not writable by untrusted users. The verifier detects observed changes during a scan, but path-based filesystem APIs cannot provide one atomic snapshot across multiple journals or prevent a privileged actor from replacing paths concurrently.

Large verifications write bounded sorting runs to a private per-operation directory in the operating system's temporary directory; small journals need no workspace. If temporary storage is unavailable or resolves inside any selected journal when sorting is needed, verification fails instead of writing inside journal evidence. Normal success, cancellation, and detectable errors remove the operation directory. An ungraceful termination such as `SIGKILL` can leave it behind; after confirming that no audit command is using it, an operator may remove the stale temporary directory manually. Recorder startup recovery separately uses managed `<journal-directory>/.bifroest-work` directories.

For file output, `export`, `decrypt`, and `merge` reject paths that could replace the identity, encryption-public-key, SFTP known-hosts, or SFTP identity files of any enabled audit log in the loaded configuration. They also reject paths that resolve inside any enabled journal or the configured filesystem session storage, including detectable symbolic-link and hard-link aliases. This protection is intentionally broader than the selected input sources and also applies with `--force`.

## Commands

* [`bifroest audit verify`](verify.md) verifies a journal without producing output.
* [`bifroest audit decrypt`](decrypt.md) is an alias for the redacted-by-default JSON Lines export; `--with-sensitive` explicitly enables decrypted private fields.
* [`bifroest audit export`](export.md) verifies and exports a journal to JSON Lines.
* [`bifroest audit merge`](merge.md) verifies and chronologically merges multiple journals.

Exports and merged streams are derived, unsigned representations. Preserve the original journal files as cryptographic evidence.
