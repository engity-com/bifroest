---
description: Alias for exporting a verified Bifröst audit journal.
---

# `bifroest audit decrypt`

`audit decrypt` is an alias for [`audit export`](export.md) and follows the same safe defaults. It verifies the complete configured journal and its signed head, not a standalone segment. It does **not** reveal confidential fields unless `--with-sensitive` is explicitly supplied; for encrypted `.beaudit`, that flag also requires the matching private age recipient key via `--decryptionIdentityFile`. Without the flag, supplied decryption identities are not loaded. Clear `.baudit` needs no decryption key but still requires `--with-sensitive` for private fields. The JSON Lines result is unsigned and must be protected.

## Syntax

`bifroest audit decrypt [flags] <auditlogName>`

See [`audit export`](export.md) for arguments, flags, output limits, and output safety rules (including the limits of shell `>` redirection). See [Encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for an example.
