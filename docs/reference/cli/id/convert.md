---
description: Convert conventional and Base58 UUID notations into a stable two-column output.
---

# `bifroest id convert`

Alias: **`bifroest id parse`**.

## Syntax

<<cli_syntax("id convert", "[flags] <id>...")>>

## Arguments

### `id` {: #argument-id }

One or more required IDs, processed in input order. Accepted forms are Base58 of exactly 16 bytes, hyphenated UUIDs (either hex case), compact hex UUIDs, braced UUIDs and `urn:uuid:…`. The nil UUID is permitted by this conversion utility; resource selectors retain their own nonzero/version/variant restrictions.

## Flags {: #id-convert-flags }

Includes [all general flags](../index.md#general-flags).

## Output

One LF-terminated line per input, no header, spaces or explanatory stdout:

```text
<lowercase-hyphenated-UUID>,<canonical-Base58>
```

All arguments are validated before output starts. Invalid input reports an error
on stderr, returns a nonzero exit status and produces no converted lines.
Configuration, keys and repositories are not opened.

## Examples

```shell
bifroest id convert 00000000-0000-0000-0000-000000000000 1111111111111111
```

```text
00000000-0000-0000-0000-000000000000,1111111111111111
00000000-0000-0000-0000-000000000000,1111111111111111
```

## Availability

<<cli_availability()>>
