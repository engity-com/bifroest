---
description: Print the producer ID of a configured local audit signing identity.
---

# `bifroest audit producer-id`

Prints the 64-character lowercase hexadecimal producer ID derived from the selected entry's **local signing private key**, not from the journal. It also works when only session recording is enabled. It does not create a missing identity or access audit records. The ID is safe to transfer; the signing private key is not.

## Syntax

`bifroest audit producer-id [flags] <auditlogName>`

## Flags

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-producer-id-", heading=3)>>
Optional configuration path; defaults to the same platform path as `bifroest run`.

## Example

On the Bifröst host after the signing identity has been created:

```shell
bifroest audit producer-id default
```

Save this value via an independently trusted channel before inspecting an offline copy. A producer ID taken only from the copied journal or a recording cannot establish producer trust. See [encrypted audit events](../../auditlog/index.md#encrypted-audit-events) for the offline workflow.
