---
description: Configure fail-closed SSH session recording, storage, delivery, and retention.
---

# Session recording

Session recording captures the output of SSH shell and exec tasks as signed [asciicast v3](https://docs.asciinema.org/manual/asciicast/v3/) content. It is configured for an [audit log](index.md), disabled by default, and can be enabled only when its parent audit log is enabled.

Each recording represents one SSH channel execution. It has its own Recording ID and is correlated with the connection, session, flow, task, and audit producer through [audit events](events.md#sessionrecordingstarted).

## Captured data and privacy

Bifröst records PTY output and terminal resize events. For non-PTY shell and exec tasks, it records stdout and stderr while preserving their stream identity and order. SFTP payloads and forwarding payloads, including direct, reverse, and agent forwarding, are not terminal recordings. An SFTP request replaced by an authorized-key forced command is recorded as the `exec` task that actually runs.

Standard input and raw keyboard input are never recorded as separate input events. Commands typed into an echoing PTY can nevertheless appear in the recorded terminal output. Input entered while terminal echo is disabled, such as a password prompt, is not captured through stdin, but programs can still expose secrets in their own output. Treat every recording and exported Cast as sensitive data.

The signed Cast is a terminal-playback representation, not a packet capture. PTY line endings are normalized for terminal playback, event times are rounded to milliseconds, and invalid UTF-8 is represented safely in standard player output while the original bytes remain in Bifröst metadata. These transformations preserve useful playback and verification but do not reproduce the original transport byte stream or scheduling exactly.

With the parent audit log's default `failurePolicy: strict`, recording is fail-closed for the affected SSH operation. If Bifröst cannot create, durably checkpoint, or seal the local recording, it closes that operation instead of continuing without a complete recording. With `failurePolicy: bestEffort`, the failure disables the complete parent audit log and recording repository until restart while the SSH operation continues without further recording. A remote-target outage does not immediately interrupt the operation because delivery is asynchronous, but retained artifacts continue to consume the local spool.

## Properties

<<property("enabled", "bool", default=False)>>
Enables session recording for flows that reference this audit log. The parent audit log must also be enabled.

<<property("directory", "File Path", "../data-type.md#file-path", default="<os specific>")>>
The exclusively managed local recording repository. Its filesystem is trusted: Bifröst does not use owners, ACLs, link checks, or protection against concurrent external mutation as a security boundary. Structural layout validation can still reject links and other unsupported entries as malformed repository state. Place it on an access-controlled local filesystem, do not modify it while Bifröst is running, and do not apply an external rotation tool to it.

The default depends on the operating system:

* Linux: `/var/lib/engity/bifroest/recordings`
* Windows: `C:\ProgramData\Engity\Bifroest\recordings`

Every enabled recording directory must be distinct. It must not overlap session storage or an enabled audit log's journal, signing identity, encryption-public-key file, recording repository, or local SFTP target key files.

<<property("compression", "Compression", "#compression")>>
Configures the compression profile used for persistent recording containers.

<<property("chunkSizeBytes", "uint64", None, default=262144)>>
Target plaintext size of independently committed chunks. The value must be between `1` and `1048577` bytes. Atomic Cast line groups can make a chunk larger than this target, but never larger than the enforced format limit.

<<property("flushInterval", "Duration", "../data-type.md#duration", default="2s")>>
Maximum interval between checkpoints while new recording content is pending. It must be positive.

<<property("flushSizeBytes", "uint64", None, default=1048576)>>
Pending output threshold that triggers a checkpoint before the interval expires. It must be positive.

<<property("maximumSpoolBytes", "uint64", None, default=107374182400)>>
Maximum total size of the managed local spool, defaulting to 100 GiB. Active and sealed artifacts, recovery work, quarantine data, delivery receipts, and temporary durable replacements all count toward this limit.

The value must be at least `chunkSizeBytes` and `flushSizeBytes`. At startup, Bifröst first reconciles recoverable temporary receipt replacements left by a crash. If the resulting managed usage still exceeds the limit, Bifröst refuses to start without deleting data. If an active operation cannot reserve additional capacity, that operation fails closed.

<<property("retainFor", "Duration", "../data-type.md#duration", default="720h")>>
How long an eligible sealed recording remains in the local repository. The value cannot be negative. `0s` prevents new automatic deletions. See [retention](#remote-delivery-and-retention) for when the period begins.

<<property("notice", ref("String", "../templating/index.md#string"), default="")>>
Optional Go template written before an interactive PTY shell starts. Bifröst adds no newline. The template can access `{{.recording.id}}` and `{{.recording.startedAt}}`.

The notice is not shown for exec tasks, forced commands, non-PTY shells, SFTP, or forwarding. The rendered notice becomes part of the recorded terminal output. A rendering or write failure prevents the target environment from starting. Do not rely on this field as the only notice mechanism when policy requires notice for task types that do not receive it.

<<property("targets", array_ref("Remote target", "remote-targets/index.md"), default="inherit")>>
Selects remote destinations for sealed recordings:

* `inherit` uses every target configured in the parent audit log.
* `false` disables remote recording delivery while leaving audit-log target delivery unchanged.
* A nonempty list defines independent recording targets using the same [S3, SFTP, and WebDAV schemas](remote-targets/index.md) as the audit log.

Every selected recording target is required. Built-in targets accept recording artifacts; a custom target must implement artifact delivery in addition to audit-segment delivery.

Changing or removing a target is rejected at startup while a sealed Recording still has an outstanding delivery or delivery-audit obligation for that target. Fully deliver and audit existing artifacts before changing their destination. Disabling Recording entirely does not open or drain its repository, so settle outstanding delivery and retention work before disabling it.

## Compression

<<property("level", "string", None, default="default", heading=3, id_prefix="compression-")>>
Compression profile for chunked Zstandard encoding. `default` is currently the only supported value.

## Formats and keys

The parent audit log supplies both the recording signing identity and the optional encryption recipient:

* Without `encryptionPublicKey` or `encryptionPublicKeyFile`, Bifröst stores signed, compressed native `.bcast` artifacts.
* With an encryption recipient, Bifröst stores signed CBOR `.becast` artifacts whose compressed event groups are independently encrypted with age.

Both native formats use the `\x89BCAST\n` magic and framed, committed canonical CBOR units. They bind a signed producer, hash chain, Cast digest, and final seal. The clear format is fully verifiable without a private key; encrypted inspection checks only the signed outer envelope. The [recording format vectors](recording-format-vectors.md) include native CBOR and separately labeled legacy `.cast`, `.cast.zst`, and binary `.becast` examples.

The local repository is permanently marked with its container format (`bcast/v1` or `becast-cbor/v1`). Directories marked with the earlier `cast-zstd/v1` or `becast/v1` formats are not migrated: configure a new empty recording directory before upgrading a server that has used those formats, and preserve the old data separately for its retention period. Changing between clear and encrypted formats also requires a new empty recording directory. The parent audit journal separately binds its encryption recipient, so every recipient change requires a new empty journal directory or a new audit log. A recipient change can reuse an encrypted recording directory only after no active recording still needs recovery with the old recipient; already sealed recordings keep their original signed recipient. Preserve the old journal, sealed recordings, and decryption identities for their required retention periods.

The audit signing identity must remain available to continue writing and recovering its repository. Existing sealed artifacts embed the corresponding public key and remain cryptographically self-verifiable, but producer trust still requires an independently retained producer ID. The producer ID is the lowercase hexadecimal SHA-256 digest of the RFC 4253 binary SSH public-key blob, which is the decoded Base64 field of an OpenSSH public-key line. Generate and retain the public key and producer ID during trusted identity provisioning, before distributing any Recording artifact.
If the signing key is lost, Bifröst will not generate a replacement while the configured Recording directory still contains state, even when Recording is temporarily disabled. Restore the original key or configure a new empty journal and Recording repository while preserving the old evidence.

Bifröst receives only the encryption public key. Keep the matching private key outside the Bifröst server and preserve every identity needed for retained BECast artifacts. Losing that private key makes their captured content permanently unavailable.

## Storage and recovery

The repository contains these managed areas:

| Path | Purpose |
| --- | --- |
| `active/` | Recordings currently being written and their signed recovery heads. |
| `sealed/` | Immutable native `.bcast` or CBOR `.becast` artifacts ready for inspection and delivery. |
| `quarantine/` | Interrupted work that could not be accepted safely. |
| `.bifroest-work/` | Durable publication and recovery work directories. |
| `.delivery/` | Signed remote-delivery receipts and audit-outbox state. |
| `.bifroest-recording-format` | Persistent repository-format binding. |
| `.bifroest-recording.lock` | Exclusive repository lock. |

Temporary format markers, signed heads, and retention tombstones can also appear while durable state transitions are in progress.

At startup, Bifröst completes interrupted publication and verifies active recordings before opening listeners. Recoverable physical tails are truncated to the last durable boundary, and interrupted active recordings are sealed as `incomplete` with reason `startup-recovery`. Correlation data in the signed lifecycle outbox permits the terminal event to be finalized even for BECast without the recipient private key. Before publication, the outbox binds the event and receipt in a non-replayable `prepared` state. Only successful atomic publication and verification promote it to `pending`. Startup alone replays pending events at least once, so an interruption after audit-journal commit but before outbox completion can produce an identical duplicate.

Invalid, not-yet-accepted work directories are moved to `quarantine/` when they can be isolated, after which startup continues. Integrity failures in accepted active or sealed state, rollback behind a signed checkpoint, and repository state that cannot be isolated follow the parent audit log's failure policy. Bifröst has no manual recording-repair command. Preserve the repository unchanged for investigation and use [`recording inspect`](../cli/recording/inspect.md) only on sealed artifact copies or safely obtained remote artifacts.

## Remote delivery and retention

Before local publication, Bifröst creates a signed receipt binding the immutable artifact to the selected target names and destinations. Delivery then runs asynchronously with retries. Configuration changes cannot silently redirect a pending artifact under an existing target name. See [remote-target delivery behavior](remote-targets/index.md#delivery-behavior) for acknowledgement and audit-outbox details.

For recordings with selected targets, `retainFor` begins at the latest durable target acknowledgement, and every selected success event must also be durably marked. Without targets, it begins when the recording is sealed. Housekeeping verifies the artifact and receipt before deleting local state and emits [retention audit events](events.md#housekeepingrecordingdeletestarted).

Retention applies only to the local recording repository. Bifröst does not delete remote copies; configure lifecycle and retention rules independently at every remote destination.

## Export and playback

Bifröst does not list, download, or play recordings. Obtain the byte-exact sealed artifact from `sealed/` or a configured remote target, then:

1. Run [`bifroest recording inspect`](../cli/recording/inspect.md) with an independently obtained producer ID.
2. Run [`bifroest recording export`](../cli/recording/export.md) with `--with-sensitive`, the same trust anchor and, for encrypted BECast, the matching private decryption identity. Export performs full Cast verification before output; encrypted inspect alone does not.
3. Protect the exported `.cast` file as sensitive plaintext.
4. Open it with a player that supports asciicast v3 and unknown comment lines.

Verification must precede playback. Bifröst-specific metadata and signatures are represented as asciicast comments, while the exported event stream remains standard asciicast v3.

## Example

This audit-log fragment enables encrypted session recordings, keeps them locally for 30 days after required delivery, and inherits the parent S3 target:

```yaml
auditlog:
  - name: security
    enabled: true
    identityFile: /etc/engity/bifroest/audit-signing-key
    encryptionPublicKeyFile: /etc/engity/bifroest/recording-recipient.pub
    journal:
      directory: /var/lib/engity/bifroest/auditlog
    recording:
      enabled: true
      directory: /var/lib/engity/bifroest/recordings
      notice: "This SSH session is recorded as {{.recording.id}}.\n"
    targets:
      - name: recording-archive
        type: s3
        bucket: company-bifroest-audit
        prefix: production
        expectedBucketOwner: "123456789012"
```

Add the fragment to a complete configuration and explicitly assign the named audit log to every flow that should be recorded with `auditlog: security`. The encryption-public-key file must exist on the Bifröst server, and the S3 target requires its normal region and credential sources.

Set `recording.targets: false` when audit segments should still be replicated but recording artifacts must remain local. To use a separate destination, replace `inherit` with a nonempty list of complete [remote-target configurations](remote-targets/index.md).
