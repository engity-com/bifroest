---
description: Stream one bounded page of verified session Recording metadata.
---

# `bifroest recording ls`

Lists sealed Recordings in one audit log, streaming entries after verification.

```shell
bifroest recording ls default --limit=20
```

## Syntax

<<cli_syntax("recording ls", "[flags] <auditlogName>")>>

<<cli_syntax("recording ls", "[flags] <auditlogName>", remote=True)>>

## Arguments

### `auditlogName` {: #argument-auditlogName }

`auditlogName` is the required configured auditlog name. Its Recording repository must be enabled. Only sealed originals are listed; active sessions are listed with [`session ls`](../session/ls.md).

## Flags {: #recording-ls-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="recording-ls-", heading=3)>>
Local configuration file; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("format", "string", default="table", id_prefix="recording-ls-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

<<flag("limit", "uint", default=100, id_prefix="recording-ls-", heading=3)>>
Maximum entries in this page, from **1 through 1,000**. `0` is invalid, not an unlimited listing.

<<flag("after", "Recording UUID", id_prefix="recording-ls-", heading=3)>>
Exclusive Recording-ID cursor. Use the last returned ID to request the next page.

## Output

The table shows ID, auditlog, signed status, start time and verification scope. Structured output contains the corresponding metadata entries. Clear Recordings receive full verification; encrypted Recordings receive outer verification without a decryption key. Outer metadata does not establish that the encrypted Cast can be decrypted and fully verified.

### Pagination

Entries are ordered by ascending Recording ID, independently of start time. Each returned entry is cryptographically verified.

The repository can change between pages. A newly created ID before the current cursor appears on a fresh listing; retention can remove an artifact during a request, causing an error and requiring a retry.

### Streaming

Streaming is the default, including when `--limit` is set. The limit controls the entry count. Entries appear as they are verified; JSON, YAML and CBOR form one result array or sequence when the command completes successfully.

A later verification, connection or output error aborts with nonzero status and leaves already emitted entries as partial output. JSON or CBOR may be unfinished. Check the command's exit status before treating a page as complete. See [Output and errors](../output.md#completion-and-errors).

## Examples

### Find a Recording and continue a listing

1. Generate a sealed Recording using [the recording guide](../../../guides/recording.md).
2. Read a page:

    ```shell
    bifroest recording ls default --limit=20 --format=json
    ```

3. Replace `LAST_RECORDING_UUID` with the last returned ID and continue:

    ```shell
    bifroest recording ls default --limit=20 --after=LAST_RECORDING_UUID --format=json
    ```

    Through management, prefix the same command with `@bifroest-admin`. Use a returned ID with [`recording show`](show.md) or [`recording play`](play.md).

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Remote metadata queries need no artifact-transfer permission or decryption key.
