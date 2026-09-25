---
description: Alias for exporting a verified Bifröst audit journal.
---

# `bifroest audit decrypt`

`audit decrypt` is an alias for [`audit export`](export.md) and can read while Bifröst writes. It never accepts a standalone segment. Confidential fields still require `--with-sensitive` and, for `.beaudit`, the matching offline age identity via `--decryptionIdentityFile`. Without `--with-sensitive`, supplied decryption identities are not loaded. The JSONL result is unsigned and must be protected.

## Syntax

`bifroest audit decrypt [flags] <auditlogName>`

See [`audit export`](export.md) for arguments, flags, output limits, and output safety rules (including the limits of shell `>` redirection). See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for an example.
