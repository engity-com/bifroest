---
description: Export the public key of a private SSH identity.
---

# `bifroest key export public`

Writes exactly one LF-terminated OpenSSH public-key line. Standard output is used by default. A file is written atomically and is not replaced unless `--force` is set.

## Syntax

`bifroest key export public [flags]`

## Flags {: #key-export-public-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("identityFile", "File Path", "../../../data-type.md#file-path", required=True, id_prefix="key-export-public-", heading=3)>>
Private key file whose public key is exported.

<<flag("comment", "string", id_prefix="key-export-public-", heading=3)>>
Optional OpenSSH public-key comment. Line breaks are not accepted.

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-public-", heading=3)>>
Output file. `-` writes to stdout.

<<flag("force", "bool", default=False, id_prefix="key-export-public-", heading=3)>>
Replaces an existing output file. Without this flag, an existing file is never modified.
