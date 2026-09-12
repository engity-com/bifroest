---
description: Verify, decrypt, export, and merge Bifröst audit journals.
---

# `bifroest audit` {: #audit-journals }

Audit commands are strictly read-only with respect to identities and journals. They load the selected configured identity without creating a missing key and use its producer ID as the trust anchor. Stop the Bifröst service before running these commands so the journal remains stable throughout verification.

Run them on quiescent storage whose journal and output parent directories are not writable by untrusted users. The verifier detects observed changes during a scan, but path-based filesystem APIs cannot provide one atomic snapshot across multiple journals or prevent a privileged actor from replacing paths concurrently.

## Commands

* [`bifroest audit verify`](verify.md) verifies a journal without producing output.
* [`bifroest audit decrypt`](decrypt.md) verifies and decrypts a journal to JSON Lines.
* [`bifroest audit export`](export.md) verifies and exports a journal to JSON Lines.
* [`bifroest audit merge`](merge.md) verifies and chronologically merges multiple journals.

Exports and merged streams are derived, unsigned representations. Preserve the original journal files as cryptographic evidence.
