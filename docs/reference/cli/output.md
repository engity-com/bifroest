---
description: Understand CLI result formats, sensitive output, streaming and failure handling.
---

# Output and errors

Command results are written to **stdout**. Logs and error messages are written to **stderr**. Logging flags such as `--log.format` do not select the result format.

## Result formats

Commands that accept `--format` support these values:

| Value | Result |
| --- | --- |
| `table` | Human-readable tables, details or status lines; the default. |
| `json` | A JSON result object or array. |
| `yaml` | A YAML result object or sequence. |
| `cbor` | A CBOR result object or array. |

The command page documents the result's content. Lists use tables, details use key/value output, verification prints its scope, and `audit producer-id` prints the ID in the default format.

Some commands have a fixed output:

| Command | Output |
| --- | --- |
| `audit export` and `audit merge` | JSON Lines: one event with its metadata per line. |
| `recording inspect` | One JSON inspection object. |
| `recording export` | Signed asciicast v3 content. |
| `recording play` | Replayed terminal output. |
| Key export commands | OpenSSH public-key, CA or `known_hosts` material. |

These commands do not accept `--format`. `--output`, where supported, chooses a destination file rather than a serialization format.

## Sensitive output

Audit event queries and JSONL exports are redacted by default. `--with-sensitive` includes confidential fields; encrypted journals additionally need the matching decryption key. A Recording export or playback always contains the complete captured terminal content and requires `--with-sensitive`.

Configuration detail commands redact arbitrary strings. The management flow's `includingCredentials` property applies to `flow show`, not to all settings queries. See the relevant command page and [Trust and verification](verification.md).

## Completion and errors

A failed command returns a nonzero exit status. Check that status before accepting output as complete.

* **`recording ls` streams** each selected entry after verifying it. A later failure leaves partial output; JSON or CBOR can remain unfinished. Accept the page as complete only when the command succeeds.
* **Audit export and merge verify all selected sources before publishing output.** A corrupt source produces no event output and leaves an existing destination file unchanged.
* **Recording export verifies before publishing content.** An existing destination is replaced only with a complete, verified export. Playback verifies its input before replaying terminal events.

Remote failures are reported on stderr where possible. A local output failure, cancellation or lost connection aborts the operation. The repository can change between listing pages; see [`recording ls`](recording/ls.md).

The integrated client also forwards server diagnostics to local stderr when a command succeeds, for example when session inspection skips a corrupt entry. It retains at most the first 16 KiB and marks truncated diagnostics. If the local diagnostic output fails, the command returns an error.

## Examples

### Save a structured session listing

1. Configure the remote alias as described in [Remote access](management.md).
2. Capture the result and accept it only when the command succeeds:

    ```shell
    bifroest @bifroest-admin session ls --format=json > sessions.json
    ```

    Handle the exit status in the calling script. The shell opens `sessions.json` before Bifröst starts; choose a separate output location. See [protected destinations](verification.md#protected-destinations).
