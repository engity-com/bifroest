---
description: Verify, decrypt, export, and merge Bifröst audit journals.
---

# `bifroest audit` {: #audit-journals }

Audit commands never create or replace identities and do not alter journal evidence files. By default, they load each selected configured signing identity without creating a missing key and use its producer ID as the trust anchor. Every signing or decryption private-key file loaded by these commands must be a regular, non-symlink file with exactly one hard link and a size of at most 1 MiB. On Unix it must be owned by the effective process user and must not be accessible by group or others. On Windows it must be owned by the current process-token owner and have a protected DACL whose allow entries name only that owner, `OWNER RIGHTS`, or `SYSTEM`.

For least-privilege offline verification, `--expectedProducerId <auditlogName>=<producer-id>` supplies an external trust anchor for one selected source. The producer ID is the 64-hex-character SHA-256 identity of the signing public key. Record it through an independently trusted provisioning channel; do not take it from the journal currently being verified or extract it automatically from a container. Repeat the flag for multiple selected sources. When a source has an explicit expected producer ID, its configured signing private key is not opened and may be absent. Without this flag, the configured private key remains mandatory, so there is no trust-anchor-less mode.

On the Bifröst host, [`bifroest audit producer-id`](producer-id.md) prints this ID from the configured signing private key without reading the journal. Preserve that value through a trusted channel before using it as an offline trust anchor. Locally, `audit verify` and `audit export` already load the platform's default configuration and use its signing identity; neither `--configuration` nor `--expectedProducerId` is needed unless selecting a different configuration or working without the signing key.

`audit verify`, `audit export`, `audit decrypt` and `audit merge` can read while Bifröst keeps writing. They check a signed committed state without pausing the service; a simultaneous rotation can cause a safe failure that can be retried. `audit producer-id` reads only the signing identity.

Commands select auditlog **names**, not segment paths. For offline export, copy the complete stopped local journal root, including `<root>/<producer-id>/head.cbor`, all sealed segments, and any active segment. Supply `--journalDirectory` and an independently trusted `--expectedProducerId` to `audit export` or `audit decrypt` instead of creating an offline configuration. The signed head is required. The server's signing private key must not be copied; keep any age recipient private key solely on the offline workstation. `audit verify` and `audit merge` still use configured sources. See the [encrypted audit example](../../auditlog/index.md#encrypted-audit-events).

S3, SFTP, and WebDAV targets deliver only sealed segments, not the head or a complete journal. There is no audit CLI command to verify a remote segment in isolation. Retain an independently trusted expected chain tip for remote-only evidence to detect suffix deletion or rollback.

Protect journal and output paths from untrusted writers. A command verifies each source up to its captured signed head; writes after that are excluded. A merge of several journals is **not** an atomic cross-journal snapshot. Detecting rollback of a valid signed head still needs an independently retained chain tip.

Large verifications write bounded sorting runs to a private per-operation directory in the operating system's temporary directory; small journals need no workspace. If temporary storage is unavailable or resolves inside any selected journal when sorting is needed, verification fails instead of writing inside journal evidence. Normal success, cancellation, and detectable errors remove the operation directory. An ungraceful termination such as `SIGKILL` can leave it behind; after confirming that no audit command is using it, an operator may remove the stale temporary directory manually. Recorder startup recovery separately uses managed `<journal-directory>/.bifroest-work` directories.

For file output, `export`, `decrypt`, and `merge` reject paths that could replace the identity, encryption-public-key, SFTP known-hosts, or SFTP identity files of any enabled audit log in the loaded configuration. They also reject paths that resolve inside any enabled journal, any enabled auditlog's recording repository, or the configured filesystem session storage, including detectable symbolic-link and hard-link aliases. This protection is intentionally broader than the selected input sources and also applies with `--force`.

## Commands

* [`bifroest audit producer-id`](producer-id.md) prints the producer ID from a configured local signing identity.
* [`bifroest audit verify`](verify.md) verifies a journal without producing output.
* [`bifroest audit decrypt`](decrypt.md) is an alias for the redacted-by-default JSON Lines export; `--with-sensitive` explicitly enables decrypted private fields.
* [`bifroest audit export`](export.md) verifies and exports a journal to JSON Lines.
* [`bifroest audit merge`](merge.md) verifies and chronologically merges multiple journals.

Exports and merged streams are derived, unsigned representations. Their public event contains only `name`, `domain`, and `outcome` when present, with provenance and timestamps in a separate envelope. Even this metadata may be sensitive; restrict access to the output. `.baudit` contains clear private fields even when its export is redacted, while `.beaudit` encrypts them. Preserve the original signed journal files as cryptographic evidence; see [public and confidential audit fields](../../../formats/audit.md#public-and-confidential-audit-fields) and [audit vectors](../../../formats/audit-vectors.md).
