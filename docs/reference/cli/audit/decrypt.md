---
description: Alias for exporting a verified Bifröst audit journal.
---

# `bifroest audit decrypt`

`audit decrypt` is an alias for [`audit export`](export.md) and follows the same safe defaults. It does **not** reveal confidential fields unless `--with-sensitive` is explicitly supplied; for `.beaudit`, that flag also requires the matching decryption identity. Without the flag, supplied decryption identities are not loaded.

## Syntax

`bifroest audit decrypt [flags] <auditlogName>`

See [`audit export`](export.md) for arguments, flags, output limits, and output safety rules (including the limits of shell `>` redirection). See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for an example.
